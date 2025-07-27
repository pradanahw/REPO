import os
import re
import requests
import joblib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import mailparser
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailAnalyzer:
    def __init__(self):
        """Initialize the email analyzer with ML models"""
        self.model = None
        self.vectorizer = None
        self.load_models()
    
    def load_models(self):
        """Load the ML models and vectorizer"""
        try:
            model_path = Path(__file__).parent / "model_phising.joblib"
            vectorizer_path = Path(__file__).parent / "tfidf_vectorizer.joblib"
            
            if not model_path.exists():
                raise FileNotFoundError(f"Model file not found: {model_path}")
            if not vectorizer_path.exists():
                raise FileNotFoundError(f"Vectorizer file not found: {vectorizer_path}")
            
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            
            logger.info("Successfully loaded ML models")
            
        except Exception as e:
            logger.error(f"Error loading ML models: {str(e)}")
            raise
    
    def parse_email_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Parse email file content and extract information"""
        try:
            # Save content to temporary file for mailparser
            temp_path = Path(f"/tmp/{filename}")
            with open(temp_path, 'wb') as f:
                f.write(file_content)
            
            # Parse email
            email = mailparser.parse_from_file(str(temp_path))
            
            # Clean up temporary file
            temp_path.unlink(missing_ok=True)
            
            # Extract email components
            subject = email.subject or ''
            sender = ''
            if email.from_:
                if isinstance(email.from_, list) and len(email.from_) > 0:
                    sender = email.from_[0][1] if len(email.from_[0]) > 1 else str(email.from_[0])
                else:
                    sender = str(email.from_)
            
            body = email.body or ''
            
            # Get headers as string for IP extraction
            headers_text = str(email.headers) if email.headers else ''
            combined_text = headers_text + "\n" + body
            
            # Extract IP addresses
            ip_addresses = self.extract_ip_addresses(combined_text)
            
            return {
                'subject': subject,
                'sender': sender,
                'body': body,
                'headers': headers_text,
                'ip_addresses': ip_addresses,
                'combined_text': combined_text
            }
            
        except Exception as e:
            logger.error(f"Error parsing email file {filename}: {str(e)}")
            raise
    
    def extract_ip_addresses(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        # Filter out private/local IPs
        public_ips = []
        for ip in ips:
            if self.is_public_ip(ip):
                public_ips.append(ip)
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(public_ips))
    
    def is_public_ip(self, ip: str) -> bool:
        """Check if IP address is public (not private/local)"""
        return not (
            ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            ip.startswith("127.") or 
            ip.startswith("172.") or
            ip.startswith("0.") or
            ip.startswith("255.")
        )
    
    def get_geolocation(self, ip: str) -> Optional[Dict[str, str]]:
        """Get geolocation data for IP address using ip-api.com"""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country,city,isp,status",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'city': data.get('city', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'isp': data.get('isp', 'Unknown')
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip}: {str(e)}")
            return None
    
    def count_urls(self, text: str) -> int:
        """Count URLs in text"""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[^\s]+\.[a-z]{2,}[^\s]*'
        urls = re.findall(url_pattern, text.lower())
        return len(urls)
    
    def count_suspicious_words(self, text: str) -> int:
        """Count suspicious words that might indicate phishing"""
        suspicious_words = [
            'urgent', 'immediate', 'verify', 'confirm', 'suspend', 'limited',
            'expire', 'click', 'login', 'update', 'security', 'account',
            'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'winner', 'congratulations', 'prize', 'lottery', 'inheritance',
            'prince', 'million', 'transfer', 'fund', 'beneficiary',
            'act now', 'limited time', 'expires today', 'final notice'
        ]
        
        text_lower = text.lower()
        count = 0
        for word in suspicious_words:
            count += text_lower.count(word)
        
        return count
    
    def predict_phishing(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict if email is phishing using ML model"""
        try:
            # Prepare input text for ML model
            input_text = f"{email_data['subject']} {email_data['body']}"
            
            # Transform text using TF-IDF vectorizer
            X_input = self.vectorizer.transform([input_text])
            
            # Make prediction
            prediction = self.model.predict(X_input)[0]
            prediction_proba = self.model.predict_proba(X_input)[0]
            
            # Get confidence score
            confidence = max(prediction_proba) * 100
            
            # Get additional analysis
            urls_detected = self.count_urls(email_data['combined_text'])
            suspicious_words = self.count_suspicious_words(email_data['combined_text'])
            
            # Get geolocation for first IP if available
            location = None
            ip_address = None
            if email_data['ip_addresses']:
                ip_address = email_data['ip_addresses'][0]
                location = self.get_geolocation(ip_address)
            
            return {
                'classification': 'PHISHING' if prediction == 1 else 'SAFE',
                'confidence': round(confidence, 1),
                'sender': email_data['sender'],
                'subject': email_data['subject'],
                'ip_address': ip_address,
                'location': location,
                'urls_detected': urls_detected,
                'suspicious_words': suspicious_words,
                'analysis_date': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error predicting phishing: {str(e)}")
            raise
    
    def analyze_email(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Complete email analysis pipeline"""
        try:
            # Parse email
            email_data = self.parse_email_file(file_content, filename)
            
            # Predict phishing
            result = self.predict_phishing(email_data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing email {filename}: {str(e)}")
            raise

# Global analyzer instance
analyzer = EmailAnalyzer()