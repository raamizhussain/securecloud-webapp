"""
ML Anomaly Detection Engine
Detects suspicious security patterns in real-time
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class SecurityAnomalyDetector:
    """Real-time security anomaly detection using Isolation Forest"""
    
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.model = None
        self.label_encoders = {}
        self.is_trained = False
        
    def load_logs(self):
        """Load logs from JSONL file"""
        logs = []
        try:
            if not os.path.exists(self.log_file_path):
                print(f"❌ Log file not found: {self.log_file_path}")
                return pd.DataFrame()
            
            with open(self.log_file_path, 'r') as f:
                for line in f:
                    try:
                        logs.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
            
            if not logs:
                print("⚠️ No logs found in file")
                return pd.DataFrame()
            
            df = pd.DataFrame(logs)
            print(f"✅ Loaded {len(df)} log entries")
            return df
            
        except Exception as e:
            print(f"❌ Error loading logs: {e}")
            return pd.DataFrame()
    
    def extract_features(self, df):
        """Extract features for ML model"""
        if df.empty:
            return pd.DataFrame()
        
        try:
            # Convert timestamp to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Time-based features
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
            
            # User behavior features
            user_stats = df.groupby('username').agg({
                'id': 'count',
                'action': lambda x: (x == 'login').sum(),
                'status': lambda x: (x == 'failed').sum()
            }).rename(columns={'id': 'total_actions', 'action': 'login_count', 'status': 'failed_count'})
            
            df = df.merge(user_stats, left_on='username', right_index=True, how='left')
            
            # Failed login rate
            df['failed_rate'] = df['failed_count'] / df['login_count'].replace(0, 1)
            
            # Action diversity
            df['action_diversity'] = df.groupby('username')['action'].transform('nunique')
            
            # Encode categorical variables
            for col in ['action', 'status', 'username']:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col].astype(str))
                else:
                    # Handle unseen labels
                    df[f'{col}_encoded'] = df[col].apply(
                        lambda x: self.label_encoders[col].transform([x])[0] 
                        if x in self.label_encoders[col].classes_ 
                        else -1
                    )
            
            # Select features for model
            feature_columns = [
                'hour', 'day_of_week', 'is_night',
                'total_actions', 'login_count', 'failed_count', 'failed_rate',
                'action_diversity', 'action_encoded', 'status_encoded', 'username_encoded'
            ]
            
            return df[feature_columns].fillna(0)
            
        except Exception as e:
            print(f"❌ Feature extraction error: {e}")
            return pd.DataFrame()
    
    def train_model(self):
        """Train Isolation Forest model on historical logs"""
        print("\n🤖 Training ML model...")
        
        # Load logs
        df = self.load_logs()
        if df.empty:
            print("❌ No data to train on")
            return False
        
        # Extract features
        features = self.extract_features(df)
        if features.empty:
            print("❌ Feature extraction failed")
            return False
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        
        self.model.fit(features)
        self.is_trained = True
        
        print(f"✅ Model trained on {len(features)} samples")
        return True
    
    def detect_anomalies(self, recent_logs_count=50, retrain=True):
        """Detect anomalies in recent logs"""
    
        # Retrain on latest data before detection
        if retrain:
            print("\n🔄 Retraining model on latest data...")
            if not self.train_model():
                return []
        
        # Load all logs
        df = self.load_logs()
        if df.empty or len(df) < recent_logs_count:
            return []
        
        # Analyze recent logs only
        recent_df = df.tail(recent_logs_count).copy()
        features = self.extract_features(recent_df)
        
        if features.empty:
            return []
        
        # Predict anomalies (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(features)
        anomaly_scores = self.model.score_samples(features)
        
        # Get anomalies
        anomalies = []
        for idx, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if pred == -1:  # Anomaly detected
                log_entry = recent_df.iloc[idx]
                anomalies.append({
                    'timestamp': log_entry['timestamp'],
                    'username': log_entry['username'],
                    'action': log_entry['action'],
                    'status': log_entry['status'],
                    'ip_address': log_entry.get('ip_address', 'Unknown'),
                    'details': log_entry.get('details', ''),
                    'anomaly_score': float(score),
                    'severity': self.calculate_severity(score)
                })
        
        return anomalies
    
    def calculate_severity(self, score):
        """Calculate severity level based on anomaly score"""
        # Scores are typically between -0.5 and 0.5
        # More negative = more anomalous
        if score < -0.3:
            return 'HIGH'
        elif score < -0.15:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def save_anomaly_report(self, anomalies):
        """Save detected anomalies to file"""
        if not anomalies:
            return
        
        report_dir = 'anomaly_reports'
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_file = os.path.join(report_dir, f'anomalies_{timestamp}.json')
        
        with open(report_file, 'w') as f:
            json.dump(anomalies, f, indent=2, default=str)
        
        print(f"📝 Anomaly report saved: {report_file}")
    
    def print_anomaly_alert(self, anomalies):
        """Print formatted anomaly alerts"""
        if not anomalies:
            print("✅ No anomalies detected")
            return
        
        print(f"\n🚨 DETECTED {len(anomalies)} ANOMALIES:\n")
        
        for i, anomaly in enumerate(anomalies, 1):
            print(f"{'='*60}")
            print(f"Anomaly #{i} - Severity: {anomaly['severity']}")
            print(f"{'='*60}")
            print(f"Time: {anomaly['timestamp']}")
            print(f"User: {anomaly['username']}")
            print(f"Action: {anomaly['action']}")
            print(f"Status: {anomaly['status']}")
            print(f"IP: {anomaly['ip_address']}")
            print(f"Details: {anomaly['details']}")
            print(f"Anomaly Score: {anomaly['anomaly_score']:.4f}")
            print()


# === THESE FUNCTIONS ARE OUTSIDE THE CLASS! ===

def detect_brute_force_attacks(log_file):
    """Specifically detect brute force patterns (rule-based + ML hybrid)"""
    print("\n🔍 Analyzing for brute force patterns...")
    
    try:
        logs = []
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except:
                    continue
        
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Look for failed login patterns
        failed_logins = df[
            (df['action'] == 'login') & 
            (df['status'].isin(['failed', 'blocked']))
        ].copy()
        
        if failed_logins.empty:
            print("✅ No failed login attempts found")
            return []
        
        # Group by username and check for rapid attempts
        brute_force_detected = []
        
        for username in failed_logins['username'].unique():
            user_fails = failed_logins[failed_logins['username'] == username].sort_values('timestamp')
            
            if len(user_fails) >= 3:  # 3+ failed attempts
                # Check if they happened rapidly (within 30 seconds)
                time_diff = (user_fails['timestamp'].max() - user_fails['timestamp'].min()).total_seconds()
                
                if time_diff < 30 and len(user_fails) >= 5:
                    severity = 'CRITICAL'
                elif time_diff < 60:
                    severity = 'HIGH'
                else:
                    severity = 'MEDIUM'
                
                brute_force_detected.append({
                    'username': username,
                    'failed_attempts': len(user_fails),
                    'time_window': f"{time_diff:.1f} seconds",
                    'first_attempt': user_fails['timestamp'].min(),
                    'last_attempt': user_fails['timestamp'].max(),
                    'severity': severity,
                    'details': f"{len(user_fails)} failed login attempts in {time_diff:.1f} seconds"
                })
        
        return brute_force_detected
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return []


def print_brute_force_alerts(attacks):
    """Print brute force attack alerts"""
    if not attacks:
        print("✅ No brute force attacks detected")
        return
    
    print(f"\n🚨 BRUTE FORCE ATTACKS DETECTED: {len(attacks)}\n")
    
    for i, attack in enumerate(attacks, 1):
        print(f"{'='*60}")
        print(f"🔥 Attack #{i} - Severity: {attack['severity']}")
        print(f"{'='*60}")
        print(f"Target User: {attack['username']}")
        print(f"Failed Attempts: {attack['failed_attempts']}")
        print(f"Time Window: {attack['time_window']}")
        print(f"First Attempt: {attack['first_attempt']}")
        print(f"Last Attempt: {attack['last_attempt']}")
        print(f"Details: {attack['details']}")
        print()


def main():
    """Main execution function"""
    print("🔍 Security Anomaly Detector Starting...\n")
    
    # Path to today's log file
    today = datetime.now().strftime('%Y-%m-%d')
    log_file = f'realtime_logs/logs_{today}.jsonl'
    
    # === PART 1: Brute Force Detection (Rule-based) ===
    brute_force_attacks = detect_brute_force_attacks(log_file)
    print_brute_force_alerts(brute_force_attacks)
    
    # === PART 2: ML Anomaly Detection ===
    detector = SecurityAnomalyDetector(log_file)
    
    # Train model
    if not detector.train_model():
        print("❌ Failed to train model")
        return
    
    # Detect anomalies
    anomalies = detector.detect_anomalies()
    
    # Display results
    detector.print_anomaly_alert(anomalies)
    
    # Save report
    if anomalies:
        detector.save_anomaly_report(anomalies)
    
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    main()
