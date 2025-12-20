"""
Attack Simulator - Creates realistic attack patterns for testing
Works standalone without Flask app
"""

import pandas as pd
import os
from datetime import datetime, timedelta
import random


def create_attack_logs():
    """Create log file with both normal behavior and attack patterns"""
    
    print("\n" + "="*80)
    print("🚨 ATTACK LOG GENERATOR - Creating Test Data")
    print("="*80 + "\n")
    
    # Load normal logs
    normal_logs_path = 'logs/security_logs.csv'
    
    if not os.path.exists(normal_logs_path):
        print(f"❌ Normal logs not found at {normal_logs_path}")
        print("   Run: python log_generator.py first")
        return False
    
    df = pd.read_csv(normal_logs_path)
    print(f"✅ Loaded {len(df)} normal log entries")
    
    # Convert to list for easier manipulation
    logs = df.to_dict('records')
    
    # Get latest timestamp
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    latest_time = df['timestamp'].max()
    
    attack_logs = []
    attack_id = len(logs) + 1
    
    # ATTACK 1: Brute Force on acc3
    print("\n🔨 Generating Attack 1: Brute Force on 'acc3'...")
    brute_force_start = latest_time + timedelta(minutes=5)
    
    for i in range(12):
        attack_logs.append({
            'id': attack_id,
            'timestamp': (brute_force_start + timedelta(seconds=i*3)).strftime('%Y-%m-%d %H:%M:%S'),
            'username': 'acc3',
            'action': 'login',
            'status': 'failed',
            'ip_address': '203.45.67.89',
            'details': f'Brute force attempt {i+1}/12 - Invalid password'
        })
        attack_id += 1
    
    print(f"   ✅ Added 12 rapid failed login attempts")
    
    # ATTACK 2: Credential Stuffing (multiple accounts from same IP)
    print("\n🔨 Generating Attack 2: Credential Stuffing...")
    cred_stuff_start = brute_force_start + timedelta(minutes=10)
    
    target_accounts = ['user1', 'user2', 'admin', 'root', 'test', 'demo']
    
    for i, username in enumerate(target_accounts):
        attack_logs.append({
            'id': attack_id,
            'timestamp': (cred_stuff_start + timedelta(seconds=i*5)).strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'action': 'login',
            'status': 'failed',
            'ip_address': '45.142.212.61',
            'details': f'Credential stuffing - Username not found: {username}'
        })
        attack_id += 1
    
    print(f"   ✅ Added {len(target_accounts)} credential stuffing attempts")
    
    # ATTACK 3: Mass File Access (Data Exfiltration Pattern)
    print("\n🔨 Generating Attack 3: Suspicious Mass File Access...")
    mass_access_start = cred_stuff_start + timedelta(minutes=15)
    
    # Compromised account accessing many files rapidly
    for i in range(25):
        attack_logs.append({
            'id': attack_id,
            'timestamp': (mass_access_start + timedelta(seconds=i*2)).strftime('%Y-%m-%d %H:%M:%S'),
            'username': 'acc2',
            'action': 'file_access',
            'status': 'success',
            'ip_address': '192.168.1.50',
            'details': f'Rapid file access pattern - file_{i+1}.pdf'
        })
        attack_id += 1
    
    print(f"   ✅ Added 25 rapid file access events")
    
    # ATTACK 4: Privilege Escalation Attempt
    print("\n🔨 Generating Attack 4: Privilege Escalation...")
    priv_esc_start = mass_access_start + timedelta(minutes=20)
    
    # Regular user trying to access admin functions
    for i in range(5):
        attack_logs.append({
            'id': attack_id,
            'timestamp': (priv_esc_start + timedelta(seconds=i*10)).strftime('%Y-%m-%d %H:%M:%S'),
            'username': 'acc1',
            'action': 'settings_change',
            'status': 'failed',
            'ip_address': '192.168.1.100',
            'details': f'Unauthorized settings change attempt - Admin privilege required'
        })
        attack_id += 1
    
    print(f"   ✅ Added 5 privilege escalation attempts")
    
    # ATTACK 5: Off-hours Access
    print("\n🔨 Generating Attack 5: Suspicious Off-Hours Activity...")
    offhours_start = latest_time.replace(hour=3, minute=30)  # 3:30 AM
    
    for i in range(8):
        attack_logs.append({
            'id': attack_id,
            'timestamp': (offhours_start + timedelta(minutes=i*5)).strftime('%Y-%m-%d %H:%M:%S'),
            'username': 'john_doe',
            'action': random.choice(['file_access', 'file_upload', 'settings_change']),
            'status': 'success',
            'ip_address': '87.251.74.123',  # Foreign IP
            'details': 'Unusual access time and location'
        })
        attack_id += 1
    
    print(f"   ✅ Added 8 off-hours access events")
    
    # Combine normal and attack logs
    all_logs = logs + attack_logs
    
    # Create DataFrame and sort by timestamp
    df_combined = pd.DataFrame(all_logs)
    df_combined['timestamp'] = pd.to_datetime(df_combined['timestamp'])
    df_combined = df_combined.sort_values('timestamp').reset_index(drop=True)
    df_combined['id'] = range(1, len(df_combined) + 1)
    
    # Save to file
    output_file = 'logs/security_logs_with_anomalies.csv'
    df_combined.to_csv(output_file, index=False)
    
    print("\n" + "="*80)
    print("📊 ATTACK LOG GENERATION SUMMARY")
    print("="*80)
    print(f"Normal logs: {len(logs)}")
    print(f"Attack logs: {len(attack_logs)}")
    print(f"Total logs: {len(df_combined)}")
    print(f"\n💾 Saved to: {output_file}")
    print("="*80)
    
    print("\n🎯 Attack Patterns Generated:")
    print("   1. ✅ Brute Force Attack (12 rapid failed logins)")
    print("   2. ✅ Credential Stuffing (6 different accounts, same IP)")
    print("   3. ✅ Mass File Access (25 files in 50 seconds)")
    print("   4. ✅ Privilege Escalation (5 unauthorized attempts)")
    print("   5. ✅ Off-Hours Activity (8 events at 3 AM from foreign IP)")
    
    print("\n✅ Ready for ML detection! Run: python ml_detector.py")
    print("="*80 + "\n")
    
    return True


def main():
    """Main execution"""
    
    print("\n" + "="*80)
    print("🚨 STANDALONE ATTACK LOG GENERATOR")
    print("="*80)
    print("\nThis generates realistic attack patterns WITHOUT needing Flask app")
    print("Perfect for testing ML anomaly detection!\n")
    print("="*80 + "\n")
    
    input("Press ENTER to generate attack logs...")
    
    if create_attack_logs():
        print("\n🎉 Success! Attack logs created!")
        print("\nNext steps:")
        print("1. Run: python ml_detector.py")
        print("2. Choose 'yes' when asked about email alerts")
        print("3. Watch AI analyze all the attacks!\n")
    else:
        print("\n❌ Failed to create attack logs")
        print("Make sure you ran: python log_generator.py first\n")


if __name__ == "__main__":
    main()
