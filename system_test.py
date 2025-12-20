"""
Complete System Test - Validates all components before AWS deployment
Tests: Database, ML Model, AI Analysis, Email Alerts, Log Processing
"""

import os
import sys
import sqlite3
import pandas as pd
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class SystemTester:
    """Comprehensive system testing"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
    
    def print_header(self, test_name):
        """Print test section header"""
        print("\n" + "="*80)
        print(f"🧪 TEST: {test_name}")
        print("="*80)
    
    def print_result(self, passed, message, warning=False):
        """Print test result"""
        if warning:
            print(f"⚠️  {message}")
            self.warnings += 1
        elif passed:
            print(f"✅ {message}")
            self.passed += 1
        else:
            print(f"❌ {message}")
            self.failed += 1
    
    # TEST 1: Environment Variables
    def test_env_variables(self):
        """Test if all required environment variables are set"""
        self.print_header("Environment Variables")
        
        required_vars = {
            'SECRET_KEY': 'Flask secret key',
            'AWS_ACCESS_KEY_ID': 'AWS access key',
            'AWS_SECRET_ACCESS_KEY': 'AWS secret key',
            'AWS_REGION': 'AWS region',
            'S3_BUCKET_NAME': 'S3 bucket name',
            'GEMINI_API_KEY': 'Gemini API key',
            'EMAIL_SENDER': 'Email sender address',
            'EMAIL_PASSWORD': 'Email app password',
        }
        
        for var, description in required_vars.items():
            value = os.getenv(var)
            if value:
                # Mask sensitive values
                if 'KEY' in var or 'PASSWORD' in var:
                    masked = value[:4] + '*' * (len(value) - 8) + value[-4:] if len(value) > 8 else '***'
                    self.print_result(True, f"{description}: {masked}")
                else:
                    self.print_result(True, f"{description}: {value}")
            else:
                self.print_result(False, f"{description}: NOT SET")
    
    # TEST 2: Database
    def test_database(self):
        """Test database connectivity and structure"""
        self.print_header("Database")
        
        db_path = 'instance/database.db'
        
        if not os.path.exists(db_path):
            self.print_result(False, f"Database not found at {db_path}")
            return
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if user table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
            if cursor.fetchone():
                self.print_result(True, "User table exists")
                
                # Count users
                cursor.execute("SELECT COUNT(*) FROM user")
                user_count = cursor.fetchone()[0]
                self.print_result(True, f"Found {user_count} users in database")
                
                # Check if email column exists
                cursor.execute("PRAGMA table_info(user)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'email' in columns:
                    self.print_result(True, "Email column exists in user table")
                else:
                    self.print_result(False, "Email column missing in user table")
            else:
                self.print_result(False, "User table not found")
            
            # Check activity_log table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_log'")
            if cursor.fetchone():
                self.print_result(True, "Activity log table exists")
                
                cursor.execute("SELECT COUNT(*) FROM activity_log")
                log_count = cursor.fetchone()[0]
                self.print_result(True, f"Found {log_count} activity logs")
            else:
                self.print_result(False, "Activity log table not found")
            
            conn.close()
            
        except Exception as e:
            self.print_result(False, f"Database error: {str(e)}")
    
    # TEST 3: Required Files
    def test_files(self):
        """Test if all required files exist"""
        self.print_header("Required Files")
        
        required_files = {
            'app.py': 'Main Flask application',
            'models.py': 'Database models',
            'ml_detector.py': 'ML anomaly detector',
            'ai_analyzer.py': 'AI incident analyzer',
            'email_alerts.py': 'Email alert system',
            'model_trainer.py': 'ML model trainer',
            'log_generator.py': 'Log generator',
            'attack_simulator.py': 'Attack simulator',
            'integrated_security_system.py': 'Integrated system',
            '.env': 'Environment variables',
            '.gitignore': 'Git ignore file',
        }
        
        for filename, description in required_files.items():
            if os.path.exists(filename):
                self.print_result(True, f"{description} ({filename})")
            else:
                self.print_result(False, f"{description} ({filename}) - MISSING")
    
    # TEST 4: Directories
    def test_directories(self):
        """Test if all required directories exist"""
        self.print_header("Required Directories")
        
        required_dirs = [
            'templates',
            'static',
            'logs',
            'models',
            'instance',
            'realtime_logs',
            'ai_analysis_reports'
        ]
        
        for dirname in required_dirs:
            if os.path.exists(dirname):
                # Count files in directory
                file_count = len([f for f in os.listdir(dirname) if os.path.isfile(os.path.join(dirname, f))])
                self.print_result(True, f"{dirname}/ directory exists ({file_count} files)")
            else:
                self.print_result(False, f"{dirname}/ directory - MISSING")
    
    # TEST 5: ML Model
    def test_ml_model(self):
        """Test ML model existence and loading"""
        self.print_header("Machine Learning Model")
        
        model_path = 'models/anomaly_model.pkl'
        
        if not os.path.exists(model_path):
            self.print_result(False, f"ML model not found at {model_path}")
            self.print_result(False, "Run: python model_trainer.py", warning=True)
            return
        
        self.print_result(True, f"ML model file exists ({os.path.getsize(model_path)} bytes)")
        
        try:
            import joblib
            model_data = joblib.load(model_path)
            
            if 'model' in model_data:
                self.print_result(True, "Model object loaded successfully")
            if 'encoders' in model_data:
                self.print_result(True, f"Label encoders found: {len(model_data['encoders'])}")
            if 'feature_columns' in model_data:
                self.print_result(True, f"Feature columns: {model_data['feature_columns']}")
                
        except Exception as e:
            self.print_result(False, f"Failed to load ML model: {str(e)}")
    
    # TEST 6: Log Files
    def test_log_files(self):
        """Test if log files exist"""
        self.print_header("Log Files")
        
        log_files = [
            'logs/security_logs.csv',
            'logs/security_logs_with_anomalies.csv'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    df = pd.read_csv(log_file)
                    self.print_result(True, f"{log_file}: {len(df)} entries")
                except Exception as e:
                    self.print_result(False, f"{log_file}: Error reading - {str(e)}")
            else:
                self.print_result(False, f"{log_file}: NOT FOUND", warning=True)
        
        # Check realtime logs
        today = datetime.now().strftime('%Y-%m-%d')
        realtime_log = f'realtime_logs/logs_{today}.jsonl'
        
        if os.path.exists(realtime_log):
            try:
                with open(realtime_log, 'r') as f:
                    line_count = sum(1 for _ in f)
                self.print_result(True, f"Today's realtime log: {line_count} entries")
            except Exception as e:
                self.print_result(False, f"Realtime log error: {str(e)}")
        else:
            self.print_result(False, "No realtime logs for today", warning=True)
    
    # TEST 7: AI Analyzer
    def test_ai_analyzer(self):
        """Test AI analyzer functionality"""
        self.print_header("AI Analyzer")
        
        try:
            from ai_analyzer import AIIncidentAnalyzer
            
            analyzer = AIIncidentAnalyzer()
            self.print_result(True, "AI analyzer initialized")
            
            # Test with sample data
            sample_anomaly = {
                'timestamp': '2025-12-19 23:00:00',
                'username': 'test_user',
                'action': 'login',
                'status': 'failed',
                'ip_address': '127.0.0.1',
                'details': 'Test anomaly',
                'anomaly_score': -0.65,
                'severity': 'HIGH'
            }
            
            print("\n   Testing AI analysis with sample data...")
            result = analyzer.analyze_anomaly(sample_anomaly)
            
            if 'ai_analysis' in result and result['ai_analysis']:
                if 'Error' not in result['ai_analysis']:
                    self.print_result(True, "AI analysis generated successfully")
                    print(f"\n   Sample output (first 200 chars):")
                    print(f"   {result['ai_analysis'][:200]}...\n")
                else:
                    self.print_result(False, f"AI analysis error: {result['ai_analysis']}")
            else:
                self.print_result(False, "AI analysis returned no results")
                
        except Exception as e:
            self.print_result(False, f"AI analyzer test failed: {str(e)}")
    
    # TEST 8: Email System
    def test_email_system(self):
        """Test email system configuration"""
        self.print_header("Email Alert System")
        
        sender = os.getenv('EMAIL_SENDER')
        password = os.getenv('EMAIL_PASSWORD')
        
        if not sender or not password:
            self.print_result(False, "Email credentials not configured")
            return
        
        self.print_result(True, f"Email sender configured: {sender}")
        
        try:
            from email_alerts import EmailAlertSystem
            
            email_system = EmailAlertSystem()
            self.print_result(True, "Email alert system initialized")
            
            # Don't actually send test email, just verify initialization
            self.print_result(True, f"SMTP server: {email_system.smtp_server}:{email_system.smtp_port}", warning=True)
            
        except Exception as e:
            self.print_result(False, f"Email system error: {str(e)}")
    
    # TEST 9: Dependencies
    def test_dependencies(self):
        """Test if all required Python packages are installed"""
        self.print_header("Python Dependencies")
        
        required_packages = [
            'flask',
            'flask_sqlalchemy',
            'flask_login',
            'pandas',
            'numpy',
            'sklearn',
            'joblib',
            'boto3',
            'python-dotenv',
            'google.generativeai',
            'schedule'
        ]
        
        for package in required_packages:
            try:
                if package == 'sklearn':
                    __import__('sklearn')
                elif package == 'python-dotenv':
                    __import__('dotenv')
                elif package == 'google.generativeai':
                    __import__('google.generativeai')
                else:
                    __import__(package)
                self.print_result(True, f"{package} installed")
            except ImportError:
                self.print_result(False, f"{package} NOT installed")
    
    # FINAL SUMMARY
    def print_summary(self):
        """Print final test summary"""
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80)
        print(f"✅ Passed:   {self.passed}")
        print(f"❌ Failed:   {self.failed}")
        print(f"⚠️  Warnings: {self.warnings}")
        print("="*80)
        
        if self.failed == 0:
            print("\n🎉 ALL TESTS PASSED! System ready for AWS deployment!")
        elif self.failed <= 3:
            print("\n⚠️  MINOR ISSUES DETECTED - Review failed tests above")
        else:
            print("\n❌ CRITICAL ISSUES - Fix errors before deployment")
        
        print("="*80 + "\n")
    
    def run_all_tests(self):
        """Run all system tests"""
        print("\n" + "="*80)
        print("🚀 CLOUD SECURITY SYSTEM - PRE-DEPLOYMENT TESTS")
        print("="*80)
        print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        self.test_env_variables()
        self.test_dependencies()
        self.test_files()
        self.test_directories()
        self.test_database()
        self.test_log_files()
        self.test_ml_model()
        self.test_ai_analyzer()
        self.test_email_system()
        
        self.print_summary()


def main():
    """Main test execution"""
    tester = SystemTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
