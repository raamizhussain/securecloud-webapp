"""
AI Incident Analyzer - Uses Google Gemini to explain security anomalies
Generates human-readable threat analysis and recommendations
"""

import json
import os
from datetime import datetime
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('models/gemini-2.5-flash')


class AIIncidentAnalyzer:
    """Analyzes security anomalies using AI to generate human-readable reports"""
    
    def __init__(self):
        self.model = model
    
    def analyze_anomaly(self, anomaly):
        """Analyze a single anomaly and generate explanation"""
        
        # Create prompt for AI
        prompt = f"""
You are a cybersecurity expert analyzing a security incident. Provide a clear, professional analysis.

INCIDENT DETAILS:
- User: {anomaly['username']}
- Action: {anomaly['action']}
- Status: {anomaly['status']}
- Time: {anomaly['timestamp']}
- IP Address: {anomaly['ip_address']}
- Details: {anomaly['details']}
- Anomaly Score: {anomaly['anomaly_score']} (more negative = more suspicious)
- Severity: {anomaly['severity']}

Provide a structured analysis with these sections:

1. WHAT HAPPENED (2-3 sentences explaining the event in plain English)

2. WHY IT'S SUSPICIOUS (2-3 sentences explaining why this is a security concern)

3. THREAT LEVEL (Rate as: CRITICAL, HIGH, MEDIUM, or LOW with brief justification)

4. RECOMMENDED ACTIONS (3-5 bullet points of specific actions to take)

5. CONFIDENCE LEVEL (Your confidence in this assessment: 0-100%)

Keep it professional, clear, and actionable. Focus on facts from the data provided.
"""
        
        try:
            # Generate AI response
            response = self.model.generate_content(prompt)
            
            return {
                'anomaly': anomaly,
                'ai_analysis': response.text,
                'analyzed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'anomaly': anomaly,
                'ai_analysis': f"Error generating analysis: {str(e)}",
                'analyzed_at': datetime.now().isoformat()
            }
    
    def analyze_multiple_anomalies(self, anomalies):
        """Analyze multiple related anomalies together"""
        
        if not anomalies:
            return None
        
        # Create summary of all anomalies
        anomaly_summary = "\n".join([
            f"- [{a['timestamp']}] User: {a['username']}, Action: {a['action']}, Status: {a['status']}, Severity: {a['severity']}"
            for a in anomalies
        ])
        
        prompt = f"""
You are a cybersecurity expert analyzing multiple related security incidents. Provide a comprehensive threat assessment.

DETECTED ANOMALIES ({len(anomalies)} total):
{anomaly_summary}

Provide a structured analysis:

1. ATTACK PATTERN SUMMARY (What type of attack or suspicious behavior is this?)

2. TIMELINE ANALYSIS (How did the events unfold? What's the progression?)

3. THREAT ASSESSMENT (Overall severity and potential impact)

4. INDICATORS OF COMPROMISE (What specific red flags are present?)

5. IMMEDIATE ACTIONS (Top 3-5 urgent steps to take right now)

6. LONG-TERM RECOMMENDATIONS (3-5 preventive measures for the future)

7. CONFIDENCE SCORE (0-100% - how confident are you in this assessment?)

Be specific, actionable, and professional.
"""
        
        try:
            response = self.model.generate_content(prompt)
            
            return {
                'anomaly_count': len(anomalies),
                'anomalies': anomalies,
                'comprehensive_analysis': response.text,
                'analyzed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'anomaly_count': len(anomalies),
                'anomalies': anomalies,
                'comprehensive_analysis': f"Error generating analysis: {str(e)}",
                'analyzed_at': datetime.now().isoformat()
            }
    
    def analyze_brute_force_attack(self, attack_data):
        """Specialized analysis for brute force attacks"""
        
        prompt = f"""
You are a cybersecurity expert analyzing a brute force attack attempt.

ATTACK DETAILS:
- Target User: {attack_data['username']}
- Failed Attempts: {attack_data['failed_attempts']}
- Time Window: {attack_data['time_window']}
- First Attempt: {attack_data['first_attempt']}
- Last Attempt: {attack_data['last_attempt']}
- Severity: {attack_data['severity']}
- Details: {attack_data['details']}

Provide analysis:

1. ATTACK TYPE (What specific type of brute force is this?)

2. ATTACKER BEHAVIOR (What does the timing/pattern tell us about the attacker?)

3. ACCOUNT STATUS (What should we do with the targeted account?)

4. IMMEDIATE RESPONSE (3-5 urgent actions to take now)

5. PREVENTION MEASURES (How to prevent this in the future?)

6. RISK ASSESSMENT (Rate 0-100 and explain)

Be specific and actionable.
"""
        
        try:
            response = self.model.generate_content(prompt)
            
            return {
                'attack_data': attack_data,
                'ai_analysis': response.text,
                'analyzed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'attack_data': attack_data,
                'ai_analysis': f"Error generating analysis: {str(e)}",
                'analyzed_at': datetime.now().isoformat()
            }
    
    def save_analysis_report(self, analysis, report_type='anomaly'):
        """Save AI analysis to file"""
        
        report_dir = 'ai_analysis_reports'
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_file = os.path.join(report_dir, f'{report_type}_analysis_{timestamp}.json')
        
        with open(report_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        print(f"\n📝 AI Analysis Report saved: {report_file}")
        
        # Also save as readable text file
        text_file = os.path.join(report_dir, f'{report_type}_analysis_{timestamp}.txt')
        
        with open(text_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("AI SECURITY INCIDENT ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            
            if 'ai_analysis' in analysis:
                f.write(analysis['ai_analysis'])
            elif 'comprehensive_analysis' in analysis:
                f.write(analysis['comprehensive_analysis'])
            
            f.write("\n\n" + "="*80 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n")
        
        print(f"📝 Human-readable report: {text_file}")
        
        return report_file


def print_ai_analysis(analysis):
    """Print formatted AI analysis to console"""
    
    print("\n" + "="*80)
    print("🤖 AI SECURITY ANALYSIS")
    print("="*80 + "\n")
    
    if 'ai_analysis' in analysis:
        print(analysis['ai_analysis'])
    elif 'comprehensive_analysis' in analysis:
        print(f"📊 Analyzing {analysis['anomaly_count']} related incidents\n")
        print(analysis['comprehensive_analysis'])
    
    print("\n" + "="*80)


def main():
    """Test the AI analyzer with sample data"""
    
    print("🤖 AI Incident Analyzer - Testing...\n")
    
    analyzer = AIIncidentAnalyzer()
    
    # Sample anomaly for testing
    sample_anomaly = {
        'timestamp': '2025-12-19 14:00:00',
        'username': 'acc3',
        'action': 'login',
        'status': 'failed',
        'ip_address': '127.0.0.1',
        'details': 'Invalid password attempt 5/5 - Account locked',
        'anomaly_score': -0.65,
        'severity': 'HIGH'
    }
    
    print("Analyzing sample anomaly...\n")
    
    result = analyzer.analyze_anomaly(sample_anomaly)
    print_ai_analysis(result)
    analyzer.save_analysis_report(result, 'test')
    
    print("\n✅ AI Analyzer working correctly!")


if __name__ == "__main__":
    main()
