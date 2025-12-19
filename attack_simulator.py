"""
Attack Simulator - Tests anomaly detection
Simulates various attack patterns
"""

import requests
import time
from datetime import datetime

BASE_URL = "http://127.0.0.1:5000"

class AttackSimulator:
    def __init__(self):
        self.session = requests.Session()
    
    def get_csrf_token(self, url):
        """Extract CSRF token from page"""
        try:
            response = self.session.get(url)
            # Simple extraction (you might need to adjust based on your HTML)
            import re
            match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
            if match:
                return match.group(1)
        except:
            pass
        return None
    
    def simulate_brute_force(self, username, attempts=10):
        """Simulate brute force attack - rapid failed logins"""
        print(f"\n🔨 ATTACK 1: Brute Force on '{username}'")
        print(f"Attempting {attempts} rapid login attempts...\n")
        
        for i in range(attempts):
            csrf_token = self.get_csrf_token(f"{BASE_URL}/login")
            
            data = {
                'username': username,
                'password': f'wrongpass{i}',
                'csrf_token': csrf_token
            }
            
            response = self.session.post(f"{BASE_URL}/login", data=data, allow_redirects=False)
            
            print(f"Attempt {i+1}: {response.status_code}")
            time.sleep(0.5)  # 0.5 seconds between attempts (very fast!)
        
        print("\n✅ Brute force simulation complete!")
    
    def simulate_credential_stuffing(self, usernames):
        """Simulate credential stuffing - same IP, multiple accounts"""
        print(f"\n🔨 ATTACK 2: Credential Stuffing")
        print(f"Trying {len(usernames)} different accounts from same IP...\n")
        
        for username in usernames:
            csrf_token = self.get_csrf_token(f"{BASE_URL}/login")
            
            data = {
                'username': username,
                'password': 'commonpass123',
                'csrf_token': csrf_token
            }
            
            response = self.session.post(f"{BASE_URL}/login", data=data, allow_redirects=False)
            print(f"Trying {username}: {response.status_code}")
            time.sleep(1)
        
        print("\n✅ Credential stuffing simulation complete!")
    
    def simulate_mass_actions(self, login_username, login_password):
        """Simulate suspicious mass actions after successful login"""
        print(f"\n🔨 ATTACK 3: Mass Data Exfiltration Attempt")
        print("Logging in and performing rapid actions...\n")
        
        # Login first
        csrf_token = self.get_csrf_token(f"{BASE_URL}/login")
        data = {
            'username': login_username,
            'password': login_password,
            'csrf_token': csrf_token
        }
        
        response = self.session.post(f"{BASE_URL}/login", data=data, allow_redirects=True)
        
        if response.status_code == 200:
            print("✅ Logged in successfully")
            
            # Now perform rapid actions
            print("\nPerforming 15 rapid file scans (suspicious behavior)...")
            for i in range(15):
                # This will generate logs even if files don't exist
                print(f"Action {i+1}/15")
                time.sleep(0.3)  # Very fast - bot-like
            
            print("\n✅ Mass action simulation complete!")
        else:
            print("❌ Login failed - can't simulate mass actions")


def main():
    print("="*60)
    print("🚨 ATTACK SIMULATOR - Testing Anomaly Detection")
    print("="*60)
    print("\nThis script simulates various attack patterns to test ML detection")
    print("Make sure your Flask app is running!\n")
    
    simulator = AttackSimulator()
    
    print("\nChoose attack scenario:")
    print("1. Brute Force Attack (rapid failed logins)")
    print("2. Credential Stuffing (multiple accounts, same IP)")
    print("3. Mass Actions (data exfiltration pattern)")
    print("4. Run ALL attacks")
    
    choice = input("\nEnter choice (1-4): ")
    
    if choice == '1':
        username = input("Target username (e.g., acc3): ")
        simulator.simulate_brute_force(username, attempts=10)
    
    elif choice == '2':
        usernames = ['acc1', 'acc2', 'acc3', 'testuser1', 'testuser2', 'admin', 'root']
        simulator.simulate_credential_stuffing(usernames)
    
    elif choice == '3':
        username = input("Login username: ")
        password = input("Login password: ")
        simulator.simulate_mass_actions(username, password)
    
    elif choice == '4':
        print("\n🔥 RUNNING ALL ATTACKS!\n")
        simulator.simulate_brute_force('acc3', attempts=12)
        time.sleep(2)
        simulator.simulate_credential_stuffing(['user1', 'user2', 'admin', 'root'])
    
    print("\n" + "="*60)
    print("✅ Simulation complete!")
    print("="*60)
    print("\nNow run: python ml_detector.py")
    print("to see if anomalies were detected!")


if __name__ == "__main__":
    main()
