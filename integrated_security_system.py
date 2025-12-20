"""
Integrated Cloud Security Monitoring System
Runs continuous monitoring with automatic anomaly detection, AI analysis, and email alerts
"""

import os
import time
import schedule
from datetime import datetime
from ml_detector import AnomalyDetector
from ai_analyzer import AIIncidentAnalyzer
from email_alerts import EmailAlertSystem
import json
import pandas as pd

class IntegratedSecuritySystem:
    """Fully automated security monitoring system"""
    
    def __init__(self):
        self.detector = AnomalyDetector()
        self.ai_analyzer = AIIncidentAnalyzer()
        self.email_system = EmailAlertSystem()
        
        # Load ML model on startup
        print("\n" + "="*80)
        print("🚀 INITIALIZING CLOUD SECURITY MONITORING SYSTEM")
        print("="*80 + "\n")
        
        if not self.detector.load_model():
            print("❌ Failed to load ML model. Train it first with model_trainer.py")
            exit(1)
        
        print("✅ System initialized successfully!\n")
    
    def run_full_scan(self, send_alerts=True):
        """Run complete security scan with detection, analysis, and alerts"""
        
        print("\n" + "="*80)
        print(f"🔍 AUTOMATED SECURITY SCAN - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        # Check for log files
        log_files = [
            'logs/security_logs_with_anomalies.csv',
            'logs/security_logs.csv',
            f'realtime_logs/logs_{datetime.now().strftime("%Y-%m-%d")}.jsonl'
        ]
        
        log_file = None
        for lf in log_files:
            if os.path.exists(lf):
                log_file = lf
                break
        
        if not log_file:
            print("⚠️  No log files found to analyze")
            print("   Generate logs using the Flask app or log_generator.py")
            return
        
        # Convert JSONL to CSV if needed
        if log_file.endswith('.jsonl'):
            log_file = self.convert_jsonl_to_csv(log_file)
        
        # Run detection and analysis
        try:
            results = self.detector.process_and_alert(log_file, send_emails=send_alerts)
            
            if results is not None:
                anomalies = results[results['is_anomaly'] == True]
                print(f"\n✅ Scan complete - {len(anomalies)} threats detected and processed")
            else:
                print("\n⚠️  Scan completed with issues")
                
        except Exception as e:
            print(f"\n❌ Error during scan: {e}")
    
    def convert_jsonl_to_csv(self, jsonl_file):
        """Convert JSONL log file to CSV for processing"""
        
        try:
            logs = []
            with open(jsonl_file, 'r') as f:
                for line in f:
                    try:
                        logs.append(json.loads(line.strip()))
                    except:
                        continue
            
            if not logs:
                return None
            
            df = pd.DataFrame(logs)
            csv_file = jsonl_file.replace('.jsonl', '_converted.csv')
            df.to_csv(csv_file, index=False)
            
            print(f"📝 Converted {len(logs)} JSONL entries to CSV")
            return csv_file
            
        except Exception as e:
            print(f"❌ Error converting JSONL: {e}")
            return None
    
    def start_continuous_monitoring(self, interval_minutes=60):
        """Start continuous monitoring with scheduled scans"""
        
        print("\n" + "="*80)
        print("🔄 STARTING CONTINUOUS MONITORING MODE")
        print("="*80)
        print(f"📊 Scan interval: Every {interval_minutes} minutes")
        print(f"📧 Email alerts: Enabled")
        print(f"🤖 AI analysis: Enabled")
        print("\nPress Ctrl+C to stop monitoring...\n")
        print("="*80 + "\n")
        
        # Schedule periodic scans
        schedule.every(interval_minutes).minutes.do(self.run_full_scan, send_alerts=True)
        
        # Run initial scan immediately
        self.run_full_scan(send_alerts=True)
        
        # Keep running
        try:
            while True:
                schedule.run_pending()
                time.sleep(30)  # Check every 30 seconds
        except KeyboardInterrupt:
            print("\n\n" + "="*80)
            print("🛑 MONITORING STOPPED BY USER")
            print("="*80 + "\n")
    
    def run_single_scan(self):
        """Run one-time security scan"""
        
        print("\n" + "="*80)
        print("🎯 SINGLE SCAN MODE")
        print("="*80 + "\n")
        
        send_alerts = input("Send email alerts? (yes/no): ").strip().lower() == 'yes'
        
        self.run_full_scan(send_alerts=send_alerts)
        
        print("\n" + "="*80)
        print("✅ SCAN COMPLETE")
        print("="*80)
        print("📁 Check 'ai_analysis_reports' folder for detailed reports")
        if send_alerts:
            print("📧 Email alerts sent to affected users")
        print("="*80 + "\n")


def main():
    """Main execution with menu"""
    
    system = IntegratedSecuritySystem()
    
    print("\n" + "="*80)
    print("🛡️  CLOUD SECURITY MONITORING SYSTEM")
    print("="*80)
    print("\nSelect monitoring mode:\n")
    print("1. 🔄 Continuous Monitoring (runs automatically every hour)")
    print("2. 🎯 Single Scan (run once now)")
    print("3. ⚡ Quick Scan (no emails, just analysis)")
    print("4. ⏰ Custom Schedule (specify interval)")
    print("5. ❌ Exit")
    print("\n" + "="*80 + "\n")
    
    choice = input("Enter choice (1-5): ").strip()
    
    if choice == '1':
        system.start_continuous_monitoring(interval_minutes=60)
    
    elif choice == '2':
        system.run_single_scan()
    
    elif choice == '3':
        system.run_full_scan(send_alerts=False)
        print("\n✅ Quick scan complete - check reports in 'ai_analysis_reports' folder")
    
    elif choice == '4':
        try:
            interval = int(input("\nEnter scan interval in minutes: ").strip())
            if interval < 1:
                print("❌ Interval must be at least 1 minute")
                return
            system.start_continuous_monitoring(interval_minutes=interval)
        except ValueError:
            print("❌ Invalid interval. Please enter a number.")
    
    elif choice == '5':
        print("\n👋 Goodbye!\n")
    
    else:
        print("\n❌ Invalid choice. Please run again and select 1-5.\n")


if __name__ == "__main__":
    main()
