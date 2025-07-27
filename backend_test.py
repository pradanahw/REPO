#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for Phishing Email Detection System
Tests all endpoints and core functionality
"""

import requests
import json
import os
import tempfile
from pathlib import Path
import time
import sys

# Get backend URL from frontend .env file
def get_backend_url():
    frontend_env_path = Path("/app/frontend/.env")
    if frontend_env_path.exists():
        with open(frontend_env_path, 'r') as f:
            for line in f:
                if line.startswith('REACT_APP_BACKEND_URL='):
                    return line.split('=', 1)[1].strip()
    return "http://localhost:8001"

BASE_URL = get_backend_url() + "/api"
print(f"Testing backend at: {BASE_URL}")

class BackendTester:
    def __init__(self):
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.test_results = []
        
    def log_test(self, test_name, success, message="", details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        if message:
            print(f"   {message}")
        if details:
            print(f"   Details: {details}")
        
        self.test_results.append({
            'test': test_name,
            'success': success,
            'message': message,
            'details': details
        })
        print()
    
    def create_sample_eml_file(self, filename="test_email.eml", phishing=False):
        """Create a sample .eml file for testing"""
        if phishing:
            content = """From: security@paypal-verification.com
To: victim@example.com
Subject: URGENT: Verify Your PayPal Account Immediately
Date: Mon, 1 Jan 2024 10:00:00 +0000
Message-ID: <123456@fake-paypal.com>
Received: from suspicious-server.com (203.0.113.1) by mail.example.com

Dear PayPal User,

Your account has been suspended due to suspicious activity. You must verify your account immediately to avoid permanent closure.

Click here to verify: http://fake-paypal-verification.com/verify

This is urgent and expires today. Act now to secure your account.

Best regards,
PayPal Security Team
"""
        else:
            content = """From: newsletter@company.com
To: user@example.com
Subject: Monthly Newsletter - January 2024
Date: Mon, 1 Jan 2024 10:00:00 +0000
Message-ID: <newsletter123@company.com>
Received: from mail.company.com (192.0.2.1) by mail.example.com

Hello,

Welcome to our monthly newsletter! Here are the latest updates from our company.

Visit our website: https://company.com

Best regards,
Company Team
"""
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False)
        temp_file.write(content)
        temp_file.close()
        return temp_file.name
    
    def test_health_check(self):
        """Test GET /api/ endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/")
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "API is running" in data["message"]:
                    self.log_test("Health Check Endpoint", True, "API is responding correctly")
                    return True
                else:
                    self.log_test("Health Check Endpoint", False, f"Unexpected response: {data}")
                    return False
            else:
                self.log_test("Health Check Endpoint", False, f"HTTP {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Health Check Endpoint", False, f"Connection error: {str(e)}")
            return False
    
    def test_analyze_valid_eml(self):
        """Test POST /api/analyze with valid .eml file"""
        try:
            # Create sample phishing email
            eml_file_path = self.create_sample_eml_file("phishing_test.eml", phishing=True)
            
            with open(eml_file_path, 'rb') as f:
                files = {'file': ('phishing_test.eml', f, 'message/rfc822')}
                response = self.session.post(f"{self.base_url}/analyze", files=files)
            
            # Clean up
            os.unlink(eml_file_path)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ['id', 'classification', 'confidence', 'sender', 'subject', 
                                 'urls_detected', 'suspicious_words', 'analysis_date', 'filename']
                
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    self.log_test("Analyze Valid EML", False, f"Missing fields: {missing_fields}")
                    return False
                
                # Validate data types and values
                if not isinstance(data['confidence'], (int, float)) or not (0 <= data['confidence'] <= 100):
                    self.log_test("Analyze Valid EML", False, f"Invalid confidence value: {data['confidence']}")
                    return False
                
                if data['classification'] not in ['PHISHING', 'SAFE']:
                    self.log_test("Analyze Valid EML", False, f"Invalid classification: {data['classification']}")
                    return False
                
                self.log_test("Analyze Valid EML", True, 
                            f"Classification: {data['classification']}, Confidence: {data['confidence']}%")
                return True
            else:
                self.log_test("Analyze Valid EML", False, f"HTTP {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Analyze Valid EML", False, f"Error: {str(e)}")
            return False
    
    def test_analyze_safe_email(self):
        """Test POST /api/analyze with safe email"""
        try:
            # Create sample safe email
            eml_file_path = self.create_sample_eml_file("safe_test.eml", phishing=False)
            
            with open(eml_file_path, 'rb') as f:
                files = {'file': ('safe_test.eml', f, 'message/rfc822')}
                response = self.session.post(f"{self.base_url}/analyze", files=files)
            
            # Clean up
            os.unlink(eml_file_path)
            
            if response.status_code == 200:
                data = response.json()
                self.log_test("Analyze Safe Email", True, 
                            f"Classification: {data['classification']}, Confidence: {data['confidence']}%")
                return True
            else:
                self.log_test("Analyze Safe Email", False, f"HTTP {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Analyze Safe Email", False, f"Error: {str(e)}")
            return False
    
    def test_analyze_invalid_file_type(self):
        """Test POST /api/analyze with invalid file type"""
        try:
            # Create a text file instead of .eml
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            temp_file.write("This is not an email file")
            temp_file.close()
            
            with open(temp_file.name, 'rb') as f:
                files = {'file': ('test.txt', f, 'text/plain')}
                response = self.session.post(f"{self.base_url}/analyze", files=files)
            
            # Clean up
            os.unlink(temp_file.name)
            
            if response.status_code == 400:
                data = response.json()
                if "Invalid file format" in data.get('detail', ''):
                    self.log_test("Invalid File Type Validation", True, "Correctly rejected non-.eml file")
                    return True
                else:
                    self.log_test("Invalid File Type Validation", False, f"Wrong error message: {data}")
                    return False
            else:
                self.log_test("Invalid File Type Validation", False, f"Expected 400, got {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Invalid File Type Validation", False, f"Error: {str(e)}")
            return False
    
    def test_analyze_empty_file(self):
        """Test POST /api/analyze with empty file"""
        try:
            # Create empty .eml file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False)
            temp_file.close()
            
            with open(temp_file.name, 'rb') as f:
                files = {'file': ('empty.eml', f, 'message/rfc822')}
                response = self.session.post(f"{self.base_url}/analyze", files=files)
            
            # Clean up
            os.unlink(temp_file.name)
            
            if response.status_code == 400:
                data = response.json()
                if "Empty file" in data.get('detail', ''):
                    self.log_test("Empty File Validation", True, "Correctly rejected empty file")
                    return True
                else:
                    self.log_test("Empty File Validation", False, f"Wrong error message: {data}")
                    return False
            else:
                self.log_test("Empty File Validation", False, f"Expected 400, got {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Empty File Validation", False, f"Error: {str(e)}")
            return False
    
    def test_get_analyses(self):
        """Test GET /api/analyses endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/analyses")
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Get Recent Analyses", True, f"Retrieved {len(data)} analyses")
                    return True
                else:
                    self.log_test("Get Recent Analyses", False, f"Expected list, got: {type(data)}")
                    return False
            else:
                self.log_test("Get Recent Analyses", False, f"HTTP {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Get Recent Analyses", False, f"Error: {str(e)}")
            return False
    
    def test_csv_download(self):
        """Test GET /api/analysis/{id}/csv endpoint"""
        try:
            # First, create an analysis to get an ID
            eml_file_path = self.create_sample_eml_file("csv_test.eml", phishing=True)
            
            with open(eml_file_path, 'rb') as f:
                files = {'file': ('csv_test.eml', f, 'message/rfc822')}
                analyze_response = self.session.post(f"{self.base_url}/analyze", files=files)
            
            os.unlink(eml_file_path)
            
            if analyze_response.status_code != 200:
                self.log_test("CSV Download", False, "Failed to create analysis for CSV test")
                return False
            
            analysis_data = analyze_response.json()
            analysis_id = analysis_data['id']
            
            # Now test CSV download
            csv_response = self.session.get(f"{self.base_url}/analysis/{analysis_id}/csv")
            
            if csv_response.status_code == 200:
                content_type = csv_response.headers.get('content-type', '')
                if 'text/csv' in content_type:
                    csv_content = csv_response.text
                    if 'Classification' in csv_content and 'Confidence' in csv_content:
                        self.log_test("CSV Download", True, "CSV file generated successfully")
                        return True
                    else:
                        self.log_test("CSV Download", False, "CSV content missing expected fields")
                        return False
                else:
                    self.log_test("CSV Download", False, f"Wrong content type: {content_type}")
                    return False
            else:
                self.log_test("CSV Download", False, f"HTTP {csv_response.status_code}: {csv_response.text}")
                return False
                
        except Exception as e:
            self.log_test("CSV Download", False, f"Error: {str(e)}")
            return False
    
    def test_csv_download_invalid_id(self):
        """Test CSV download with invalid analysis ID"""
        try:
            fake_id = "non-existent-id-12345"
            response = self.session.get(f"{self.base_url}/analysis/{fake_id}/csv")
            
            if response.status_code == 404:
                self.log_test("CSV Download Invalid ID", True, "Correctly returned 404 for invalid ID")
                return True
            else:
                self.log_test("CSV Download Invalid ID", False, f"Expected 404, got {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("CSV Download Invalid ID", False, f"Error: {str(e)}")
            return False
    
    def test_status_endpoints(self):
        """Test status check endpoints"""
        try:
            # Test POST /api/status
            status_data = {"client_name": "test_client"}
            post_response = self.session.post(f"{self.base_url}/status", json=status_data)
            
            if post_response.status_code != 200:
                self.log_test("Status Endpoints", False, f"POST status failed: {post_response.status_code}")
                return False
            
            # Test GET /api/status
            get_response = self.session.get(f"{self.base_url}/status")
            
            if get_response.status_code == 200:
                data = get_response.json()
                if isinstance(data, list):
                    self.log_test("Status Endpoints", True, f"Status endpoints working, {len(data)} records")
                    return True
                else:
                    self.log_test("Status Endpoints", False, f"GET status returned non-list: {type(data)}")
                    return False
            else:
                self.log_test("Status Endpoints", False, f"GET status failed: {get_response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Status Endpoints", False, f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all backend tests"""
        print("=" * 60)
        print("PHISHING EMAIL DETECTION BACKEND API TESTS")
        print("=" * 60)
        print()
        
        tests = [
            self.test_health_check,
            self.test_analyze_valid_eml,
            self.test_analyze_safe_email,
            self.test_analyze_invalid_file_type,
            self.test_analyze_empty_file,
            self.test_get_analyses,
            self.test_csv_download,
            self.test_csv_download_invalid_id,
            self.test_status_endpoints
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            if test():
                passed += 1
        
        print("=" * 60)
        print(f"TEST SUMMARY: {passed}/{total} tests passed")
        print("=" * 60)
        
        if passed == total:
            print("🎉 ALL TESTS PASSED!")
            return True
        else:
            print(f"❌ {total - passed} tests failed")
            return False

def main():
    """Main test execution"""
    tester = BackendTester()
    success = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()