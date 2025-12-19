"""
Security Log Generator - Creates realistic security logs for training
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

def generate_logs(num_entries=1000, output_file='logs/security_logs.csv'):
    """Generate realistic security logs"""
    
    print("\n" + "="*80)
    print("📝 GENERATING SECURITY LOGS")
    print("="*80 + "\n")
    
    # Sample users
    users = ['admin', 'user1', 'user2', 'acc1', 'acc2', 'acc3', 'john_doe', 'jane_smith']
    
    # Sample actions
    actions = ['login', 'logout', 'file_access', 'file_upload', 'settings_change', 'password_change']
    
    # Sample statuses
    statuses = ['success', 'failed']
    
    # Sample IPs
    ips = [f'192.168.1.{i}' for i in range(1, 50)]
    
    logs = []
    
    print(f"Generating {num_entries} log entries...")
    
    # Start time (last 7 days)
    start_time = datetime.now() - timedelta(days=7)
    
    for i in range(num_entries):
        # Generate realistic timestamp
        timestamp = start_time + timedelta(
            days=random.randint(0, 7),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        # Pick random attributes
        username = random.choice(users)
        action = random.choice(actions)
        
        # Most actions succeed (90% success rate for normal behavior)
        if random.random() < 0.9:
            status = 'success'
            details = f"{action.replace('_', ' ').title()} completed successfully"
        else:
            status = 'failed'
            details = f"{action.replace('_', ' ').title()} failed - Invalid credentials"
        
        ip_address = random.choice(ips)
        
        log_entry = {
            'id': i + 1,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'action': action,
            'status': status,
            'ip_address': ip_address,
            'details': details
        }
        
        logs.append(log_entry)
    
    # Create DataFrame
    df = pd.DataFrame(logs)
    
    # Sort by timestamp
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    
    print(f"✅ Generated {len(df)} log entries")
    print(f"💾 Saved to: {output_file}")
    print(f"📊 Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    
    # Statistics
    print(f"\n📈 Log Statistics:")
    print(f"   - Unique users: {df['username'].nunique()}")
    print(f"   - Actions: {', '.join(df['action'].unique())}")
    print(f"   - Success rate: {(df['status']=='success').sum() / len(df) * 100:.1f}%")
    print(f"   - Failed attempts: {(df['status']=='failed').sum()}")
    
    print("\n" + "="*80)
    print("✅ LOG GENERATION COMPLETE!")
    print("="*80)
    print("\nNext step: Run model_trainer.py to train the ML model")
    print("="*80 + "\n")
    
    return df


def main():
    """Main execution"""
    
    # Generate 1000 normal log entries
    generate_logs(num_entries=1000, output_file='logs/security_logs.csv')


if __name__ == "__main__":
    main()
