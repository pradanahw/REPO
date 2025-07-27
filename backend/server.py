from fastapi import FastAPI, APIRouter, File, UploadFile, HTTPException
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime
import csv
import io
from email_analyzer import analyzer

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define Models
class AnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    classification: str
    confidence: float
    sender: str
    subject: str
    body: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[dict] = None
    urls_detected: int
    suspicious_words: int
    analysis_date: str
    filename: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "AI Phishing Detector API is running"}

@api_router.post("/analyze", response_model=AnalysisResult)
async def analyze_email(file: UploadFile = File(...)):
    """Analyze uploaded .eml email file for phishing detection"""
    
    # Validate file type
    if not file.filename.lower().endswith('.eml'):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file format. Only .eml files are accepted."
        )
    
    # Validate file size (10MB limit)
    if file.size and file.size > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="File too large. Maximum size allowed is 10MB."
        )
    
    try:
        # Read file content
        file_content = await file.read()
        
        if not file_content:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        # Analyze email
        analysis_result = analyzer.analyze_email(file_content, file.filename)
        
        # Create result model
        result = AnalysisResult(
            classification=analysis_result['classification'],
            confidence=analysis_result['confidence'],
            sender=analysis_result['sender'],
            subject=analysis_result['subject'],
            body=analysis_result['body'],
            ip_address=analysis_result['ip_address'],
            location=analysis_result['location'],
            urls_detected=analysis_result['urls_detected'],
            suspicious_words=analysis_result['suspicious_words'],
            analysis_date=analysis_result['analysis_date'],
            filename=file.filename
        )
        
        # Store result in database
        await db.analysis_results.insert_one(result.dict())
        
        return result
        
    except Exception as e:
        logging.error(f"Error analyzing email: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing email: {str(e)}"
        )

@api_router.get("/analysis/{analysis_id}/csv")
async def download_analysis_csv(analysis_id: str):
    """Download analysis result as CSV"""
    try:
        # Get analysis result from database
        result = await db.analysis_results.find_one({"id": analysis_id})
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write CSV headers and data
        writer.writerow(['Field', 'Value'])
        writer.writerow(['Classification', result['classification']])
        writer.writerow(['Confidence', f"{result['confidence']}%"])
        writer.writerow(['Sender', result['sender']])
        writer.writerow(['Subject', result['subject']])
        writer.writerow(['IP Address', result['ip_address'] or 'N/A'])
        
        location_str = 'N/A'
        if result['location']:
            location_str = f"{result['location'].get('city', '')}, {result['location'].get('country', '')}"
        writer.writerow(['Location', location_str])
        
        writer.writerow(['URLs Detected', result['urls_detected']])
        writer.writerow(['Suspicious Words', result['suspicious_words']])
        writer.writerow(['Analysis Date', result['analysis_date']])
        writer.writerow(['Filename', result['filename']])
        
        # Prepare response
        output.seek(0)
        csv_content = output.getvalue()
        output.close()
        
        # Create streaming response
        def generate():
            yield csv_content
        
        filename = f"email-analysis-{result['filename']}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return StreamingResponse(
            io.BytesIO(csv_content.encode('utf-8')),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error generating CSV: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error generating CSV: {str(e)}"
        )

@api_router.get("/analyses", response_model=List[AnalysisResult])
async def get_recent_analyses(limit: int = 10):
    """Get recent analysis results"""
    try:
        analyses = await db.analysis_results.find().sort("timestamp", -1).limit(limit).to_list(limit)
        return [AnalysisResult(**analysis) for analysis in analyses]
    except Exception as e:
        logging.error(f"Error fetching analyses: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching analyses: {str(e)}"
        )

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()