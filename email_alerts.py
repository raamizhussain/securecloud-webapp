"""
Email Alert System - Sends security incident notifications
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


class EmailAlertSystem:
    """Sends email alerts for security incidents"""
    
    def __init__(self):
        self.sender_email = os.getenv('EMAIL_SENDER')
        self.sender_password = os.getenv('EMAIL_PASSWORD')
        self.smtp_server = os.getenv('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('EMAIL_SMTP_PORT', 587))
    
    def send_anomaly_alert(self, recipient_email, anomaly_data, ai_analysis):
        """Send email alert for detected anomaly with AI analysis"""
        
        subject = f"🚨 SECURITY ALERT: {anomaly_data['severity']} - Anomaly Detected for {anomaly_data['username']}"
        
        # Create HTML email body
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #d32f2f; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .severity-HIGH {{ background-color: #ffebee; border-left: 4px solid #d32f2f; padding: 10px; margin: 10px 0; }}
                .severity-CRITICAL {{ background-color: #fff3e0; border-left: 4px solid #e65100; padding: 10px; margin: 10px 0; }}
                .severity-MEDIUM {{ background-color: #fff9c4; border-left: 4px solid #f57f17; padding: 10px; margin: 10px 0; }}
                .details {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .ai-section {{ background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .footer {{ background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
                h2 {{ color: #1976d2; }}
                h3 {{ color: #0d47a1; }}
                pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 SECURITY INCIDENT DETECTED</h1>
                <p>Automated Security Monitoring System</p>
            </div>
            
            <div class="content">
                <div class="severity-{anomaly_data['severity']}">
                    <h2>⚠️ Severity: {anomaly_data['severity']}</h2>
                    <p><strong>Anomaly Score:</strong> {anomaly_data['anomaly_score']:.2f} (more negative = more suspicious)</p>
                </div>
                
                <div class="details">
                    <h2>📋 Incident Details</h2>
                    <ul>
                        <li><strong>Account:</strong> {anomaly_data['username']}</li>
                        <li><strong>Action:</strong> {anomaly_data['action']}</li>
                        <li><strong>Status:</strong> {anomaly_data['status']}</li>
                        <li><strong>Timestamp:</strong> {anomaly_data['timestamp']}</li>
                        <li><strong>IP Address:</strong> {anomaly_data['ip_address']}</li>
                        <li><strong>Details:</strong> {anomaly_data['details']}</li>
                    </ul>
                </div>
                
                <div class="ai-section">
                    <h2>🤖 AI Security Analysis</h2>
                    <pre>{ai_analysis}</pre>
                </div>
                
                <div class="details">
                    <h3>🔐 Immediate Actions Required</h3>
                    <ul>
                        <li>Verify if this activity was authorized</li>
                        <li>Check for additional suspicious activity from this account</li>
                        <li>Consider temporarily locking the account if unauthorized</li>
                        <li>Review the AI recommendations above</li>
                        <li>Contact security team if necessary</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>This is an automated alert from Cloud Security Monitoring System</p>
                <p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Do not reply to this email. Contact your security administrator for assistance.</p>
            </div>
        </body>
        </html>
        """
        
        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.sender_email
            message['To'] = recipient_email
            
            # Attach HTML content
            html_part = MIMEText(html_body, 'html')
            message.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
            
            print(f"✅ Alert email sent to {recipient_email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email: {str(e)}")
            return False
    
    def send_brute_force_alert(self, recipient_email, attack_data, ai_analysis):
        """Send email alert for brute force attack"""
        
        subject = f"🚨 CRITICAL: Brute Force Attack Detected on {attack_data['username']}"
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #b71c1c; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .critical {{ background-color: #ffccbc; border-left: 4px solid #b71c1c; padding: 15px; margin: 10px 0; }}
                .details {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .ai-section {{ background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .footer {{ background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
                h2 {{ color: #c62828; }}
                pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 BRUTE FORCE ATTACK DETECTED</h1>
                <p>IMMEDIATE ACTION REQUIRED</p>
            </div>
            
            <div class="content">
                <div class="critical">
                    <h2>⛔ CRITICAL SECURITY INCIDENT</h2>
                    <p>Multiple failed login attempts detected - possible account compromise attempt</p>
                </div>
                
                <div class="details">
                    <h2>📋 Attack Details</h2>
                    <ul>
                        <li><strong>Target Account:</strong> {attack_data['username']}</li>
                        <li><strong>Failed Attempts:</strong> {attack_data['failed_attempts']}</li>
                        <li><strong>Time Window:</strong> {attack_data['time_window']}</li>
                        <li><strong>First Attempt:</strong> {attack_data['first_attempt']}</li>
                        <li><strong>Last Attempt:</strong> {attack_data['last_attempt']}</li>
                        <li><strong>Severity:</strong> {attack_data['severity']}</li>
                    </ul>
                </div>
                
                <div class="ai-section">
                    <h2>🤖 AI Threat Analysis</h2>
                    <pre>{ai_analysis}</pre>
                </div>
                
                <div class="critical">
                    <h3>🚨 IMMEDIATE ACTIONS</h3>
                    <ul>
                        <li><strong>LOCK THE ACCOUNT IMMEDIATELY</strong></li>
                        <li>Contact the account owner via alternative communication</li>
                        <li>Force password reset</li>
                        <li>Review recent successful logins</li>
                        <li>Check for data exfiltration</li>
                        <li>Alert security team</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>🚨 CRITICAL SECURITY ALERT - Cloud Security Monitoring System</p>
                <p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </body>
        </html>
        """
        
        try:
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.sender_email
            message['To'] = recipient_email
            
            html_part = MIMEText(html_body, 'html')
            message.attach(html_part)
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
            
            print(f"✅ CRITICAL alert email sent to {recipient_email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email: {str(e)}")
            return False


def test_email_system():
    """Test the email alert system"""
    
    print("📧 Testing Email Alert System...\n")
    
    email_system = EmailAlertSystem()
    
    # Test anomaly data
    test_anomaly = {
        'username': 'test_user',
        'action': 'login',
        'status': 'failed',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip_address': '192.168.1.100',
        'details': 'Test alert - Invalid password',
        'anomaly_score': -0.75,
        'severity': 'HIGH'
    }
    
    test_ai_analysis = """
1. WHAT HAPPENED
This is a test security alert to verify the email notification system is working correctly.

2. WHY IT'S SUSPICIOUS
This is a simulated anomaly for testing purposes.

3. THREAT LEVEL
TEST - This is a test alert only.

4. RECOMMENDED ACTIONS
- Verify email system is working
- Check email formatting
- Confirm AI analysis is included

5. CONFIDENCE LEVEL
100% (This is a test)
"""
    
    recipient = input("Enter your email address to receive test alert: ").strip()
    
    if recipient:
        email_system.send_anomaly_alert(recipient, test_anomaly, test_ai_analysis)
        print("\n✅ Test complete! Check your email inbox.")
    else:
        print("❌ No email address provided.")


if __name__ == "__main__":
    test_email_system()
