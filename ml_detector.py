"""
Anomaly Detection System with AI Analysis and Email Alerts
Detects unusual patterns in security logs and sends automated alerts
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os
from datetime import datetime, timedelta
import json
import sqlite3

# Import our AI analyzer and email system
from ai_analyzer import AIIncidentAnalyzer, print_ai_analysis
from email_alerts import EmailAlertSystem


class AnomalyDetector:
    """Advanced anomaly detection with AI analysis and email alerts"""
    
    def __init__(self, model_path='models/anomaly_model.pkl', db_path='instance/database.db'):
        self.model_path = model_path
        self.db_path = db_path  # Changed to instance/database.db
        self.model = None
        self.label_encoders = {}
        self.feature_columns = ['action_encoded', 'status_encoded', 'hour', 'minute']
        
        # Initialize AI analyzer and email system
        self.ai_analyzer = AIIncidentAnalyzer()
        self.email_system = EmailAlertSystem()
    
    def get_user_email(self, username):
        """Fetch user email from database automatically"""
        try:
            # Check if database exists
            if not os.path.exists(self.db_path):
                print(f"⚠️  Database not found at {self.db_path}")
                print(f"   Using fallback admin email")
                return os.getenv('EMAIL_SENDER')
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query user email from database
            cursor.execute("SELECT email FROM user WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0]:
                print(f"✅ Found email for {username}: {result[0]}")
                return result[0]
            else:
                # Fallback to admin email if user not found
                print(f"⚠️  No email found for user '{username}' in database")
                print(f"   Using fallback admin email")
                return os.getenv('EMAIL_SENDER')
                
        except Exception as e:
            print(f"❌ Database error fetching email for {username}: {e}")
            print(f"   Using fallback admin email")
            return os.getenv('EMAIL_SENDER')
        
    def load_model(self):
        """Load the trained anomaly detection model"""
        if os.path.exists(self.model_path):
            model_data = joblib.load(self.model_path)
            self.model = model_data['model']
            self.label_encoders = model_data['encoders']
            print(f"✅ Model loaded from {self.model_path}")
            return True
        else:
            print(f"❌ Model not found at {self.model_path}")
            return False
    
    def prepare_features(self, df):
        """Prepare features for anomaly detection"""
        df = df.copy()
        
        # Encode categorical variables
        for col in ['action', 'status']:
            if col in df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col])
                else:
                    # Handle unseen labels
                    le = self.label_encoders[col]
                    df[f'{col}_encoded'] = df[col].apply(
                        lambda x: le.transform([x])[0] if x in le.classes_ else -1
                    )
        
        # Extract time features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['minute'] = df['timestamp'].dt.minute
        
        return df
    
    def detect_anomalies(self, df, threshold=-0.5):
        """Detect anomalies in the log data"""
        if self.model is None:
            print("❌ Model not loaded. Call load_model() first.")
            return None
        
        # Prepare features
        df_processed = self.prepare_features(df)
        
        # Get features for prediction
        X = df_processed[self.feature_columns]
        
        # Predict anomalies
        anomaly_scores = self.model.decision_function(X)
        predictions = self.model.predict(X)
        
        # Add results to dataframe
        df_processed['anomaly_score'] = anomaly_scores
        df_processed['is_anomaly'] = predictions == -1
        
        # Flag severe anomalies
        df_processed['severity'] = df_processed['anomaly_score'].apply(
            lambda x: 'CRITICAL' if x < -0.7 else 'HIGH' if x < -0.5 else 'MEDIUM' if x < -0.3 else 'LOW'
        )
        
        return df_processed
    
    def analyze_brute_force(self, df, time_window_minutes=5, threshold=3):
        """Detect brute force attacks (multiple failed login attempts)"""
        
        # Filter failed login attempts
        failed_logins = df[
            (df['action'] == 'login') & 
            (df['status'] == 'failed')
        ].copy()
        
        if failed_logins.empty:
            return []
        
        failed_logins['timestamp'] = pd.to_datetime(failed_logins['timestamp'])
        failed_logins = failed_logins.sort_values('timestamp')
        
        brute_force_attacks = []
        
        # Group by username
        for username in failed_logins['username'].unique():
            user_fails = failed_logins[failed_logins['username'] == username]
            
            # Check for rapid failed attempts
            for i in range(len(user_fails)):
                current_time = user_fails.iloc[i]['timestamp']
                time_threshold = current_time + timedelta(minutes=time_window_minutes)
                
                # Count failures in time window
                window_fails = user_fails[
                    (user_fails['timestamp'] >= current_time) &
                    (user_fails['timestamp'] <= time_threshold)
                ]
                
                if len(window_fails) >= threshold:
                    attack_info = {
                        'username': username,
                        'failed_attempts': len(window_fails),
                        'first_attempt': str(window_fails.iloc[0]['timestamp']),
                        'last_attempt': str(window_fails.iloc[-1]['timestamp']),
                        'time_window': f"{time_window_minutes} minutes",
                        'severity': 'CRITICAL' if len(window_fails) >= 5 else 'HIGH',
                        'details': f"Detected {len(window_fails)} failed login attempts in {time_window_minutes} minutes"
                    }
                    
                    # Avoid duplicates
                    if not any(a['username'] == username for a in brute_force_attacks):
                        brute_force_attacks.append(attack_info)
                    break
        
        return brute_force_attacks
    
    def process_and_alert(self, log_file, send_emails=True):
        """Process logs, detect anomalies, analyze with AI, and send email alerts"""
        
        print("\n" + "="*80)
        print("🔍 CLOUD SECURITY MONITORING SYSTEM - FULL ANALYSIS")
        print("="*80 + "\n")
        
        # Load logs
        print(f"📂 Loading logs from: {log_file}")
        df = pd.read_csv(log_file)
        print(f"✅ Loaded {len(df)} log entries\n")
        
        # Detect anomalies
        print("🤖 Running anomaly detection...")
        results = self.detect_anomalies(df)
        
        if results is None:
            return
        
        # Find anomalies
        anomalies = results[results['is_anomaly'] == True]
        
        print(f"⚠️  Found {len(anomalies)} anomalies\n")
        
        # Detect brute force attacks
        print("🔒 Checking for brute force attacks...")
        brute_force_attacks = self.analyze_brute_force(df)
        print(f"🚨 Found {len(brute_force_attacks)} potential brute force attacks\n")
        
        # Process each anomaly with AI and send alerts
        if len(anomalies) > 0:
            print("="*80)
            print("🤖 AI ANALYSIS OF DETECTED ANOMALIES")
            print("="*80 + "\n")
            
            for idx, row in anomalies.iterrows():
                anomaly_data = {
                    'timestamp': str(row['timestamp']),
                    'username': row['username'],
                    'action': row['action'],
                    'status': row['status'],
                    'ip_address': row['ip_address'],
                    'details': row['details'],
                    'anomaly_score': row['anomaly_score'],
                    'severity': row['severity']
                }
                
                print(f"\n📊 Analyzing anomaly for user: {row['username']}")
                
                # Get AI analysis
                ai_result = self.ai_analyzer.analyze_anomaly(anomaly_data)
                
                # Print analysis
                print_ai_analysis(ai_result)
                
                # Save analysis report
                self.ai_analyzer.save_analysis_report(ai_result, f"anomaly_{row['username']}")
                
                # Send email alert - AUTOMATICALLY FETCH EMAIL FROM DATABASE
                if send_emails:
                    user_email = self.get_user_email(row['username'])
                    print(f"\n📧 Sending alert email to: {user_email}")
                    self.email_system.send_anomaly_alert(
                        user_email,
                        anomaly_data,
                        ai_result['ai_analysis']
                    )
                
                print("\n" + "-"*80)
        
        # Process brute force attacks
        if len(brute_force_attacks) > 0:
            print("\n" + "="*80)
            print("🚨 BRUTE FORCE ATTACK ANALYSIS")
            print("="*80 + "\n")
            
            for attack in brute_force_attacks:
                print(f"\n⚠️  Analyzing brute force attack on: {attack['username']}")
                
                # Get AI analysis
                ai_result = self.ai_analyzer.analyze_brute_force_attack(attack)
                
                # Print analysis
                print_ai_analysis(ai_result)
                
                # Save analysis report
                self.ai_analyzer.save_analysis_report(ai_result, f"brute_force_{attack['username']}")
                
                # Send email alert - AUTOMATICALLY FETCH EMAIL FROM DATABASE
                if send_emails:
                    user_email = self.get_user_email(attack['username'])
                    print(f"\n📧 Sending CRITICAL alert email to: {user_email}")
                    self.email_system.send_brute_force_alert(
                        user_email,
                        attack,
                        ai_result['ai_analysis']
                    )
                
                print("\n" + "-"*80)
        
        # Summary
        print("\n" + "="*80)
        print("📊 ANALYSIS SUMMARY")
        print("="*80)
        print(f"Total log entries processed: {len(df)}")
        print(f"Anomalies detected: {len(anomalies)}")
        print(f"Brute force attacks detected: {len(brute_force_attacks)}")
        print(f"Email alerts sent: {len(anomalies) + len(brute_force_attacks) if send_emails else 0}")
        print(f"AI analysis reports generated: {len(anomalies) + len(brute_force_attacks)}")
        print("="*80 + "\n")
        
        return results


def main():
    """Main execution function"""
    
    detector = AnomalyDetector()
    
    # Load the trained model
    if not detector.load_model():
        print("❌ Cannot proceed without trained model. Run model_trainer.py first.")
        return
    
    # Process logs with full analysis
    log_file = 'logs/security_logs_with_anomalies.csv'
    
    if not os.path.exists(log_file):
        print(f"❌ Log file not found: {log_file}")
        return
    
    # Ask user if they want to send emails
    send_emails = input("\n📧 Send email alerts? (yes/no): ").strip().lower() == 'yes'
    
    # Run full analysis
    results = detector.process_and_alert(log_file, send_emails=send_emails)
    
    print("\n✅ Complete security analysis finished!")
    print("📁 Check 'ai_analysis_reports' folder for detailed AI reports")
    if send_emails:
        print("📧 Check your email for security alerts")


if __name__ == "__main__":
    main()
