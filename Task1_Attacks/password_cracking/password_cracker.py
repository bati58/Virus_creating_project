#!/usr/bin/env python3
"""
Password Cracking Simulation (Educational)
Demonstrates dictionary attack concepts
"""

import hashlib
import time

class PasswordCracker:
    def __init__(self):
        self.common_passwords = [
            "password", "123456", "12345678", "1234", "qwerty",
            "12345", "dragon", "baseball", "football", "letmein",
            "monkey", "abc123", "111111", "mustang", "access",
            "shadow", "master", "michael", "superman", "696969"
        ]
    
    def create_password_file(self):
        """Create a test password file with hashes"""
        print("[*] Creating test password database...")
        
        with open("password_database.txt", "w") as f:
            f.write("# Simulated Password Database (MD5 Hashes)\n")
            f.write("# Format: username:hash\n")
            
            test_users = [
                ("abel", "password123"),
                ("bati", "dragon"),
                ("chala", "letmein"),
                ("dave", "qwerty"),
                ("elsabet", "123456"),
                ("admin", "P@ssw0rd!"),  # Stronger password
            ]
            
            for username, password in test_users:
                # Create MD5 hash
                hash_md5 = hashlib.md5(password.encode()).hexdigest()
                f.write(f"{username}:{hash_md5}\n")
        
        print("[+] Created password_database.txt")
        print("[+] Sample users added with weak passwords")
    
    def dictionary_attack(self):
        """Perform dictionary attack on password database"""
        print("\n[*] Starting Dictionary Attack...")
        print("[*] Loading common passwords...")
        
        # Load target hashes
        targets = {}
        with open("password_database.txt", "r") as f:
            for line in f:
                if ":" in line and not line.startswith("#"):
                    username, hash_val = line.strip().split(":")
                    targets[username] = hash_val
        
        print(f"[*] Loaded {len(targets)} target accounts")
        print("[*] Beginning crack attempt...\n")
        
        cracked = []
        start_time = time.time()
        
        # Try each password against each hash
        attempts = 0
        for password in self.common_passwords:
            hash_attempt = hashlib.md5(password.encode()).hexdigest()
            
            for username, hash_val in targets.items():
                attempts += 1
                if hash_attempt == hash_val:
                    cracked.append((username, password))
                    print(f"[!] CRACKED: {username}:{password}")
        
        elapsed = time.time() - start_time
        
        # Display results
        print("\n" + "="*50)
        print("PASSWORD CRACKING RESULTS")
        print("="*50)
        print(f"Time Elapsed:     {elapsed:.2f} seconds")
        print(f"Attempts Made:    {attempts}")
        print(f"Passwords Tried:  {len(self.common_passwords)}")
        print(f"Accounts Cracked: {len(cracked)}/{len(targets)}")
        
        if cracked:
            print("\nCracked Accounts:")
            for username, password in cracked:
                print(f"  {username:10} -> {password}")
        
        # Save results
        with open("cracking_results.txt", "w") as f:
            f.write("Password Cracking Results\n")
            f.write("="*40 + "\n")
            f.write(f"Cracked: {len(cracked)}/{len(targets)} accounts\n\n")
            for username, password in cracked:
                f.write(f"{username}:{password}\n")
        
        print(f"\n[+] Results saved to cracking_results.txt")
    
    def hash_calculator(self):
        """Tool to calculate hashes for educational purposes"""
        print("\n[*] Hash Calculator Tool")
        print("[*] Enter passwords to see their hash values")
        
        while True:
            password = input("\nEnter password (or 'quit' to exit): ")
            if password.lower() == 'quit':
                break
            
            print("\nHash Values:")
            print(f"MD5:      {hashlib.md5(password.encode()).hexdigest()}")
            print(f"SHA-1:    {hashlib.sha1(password.encode()).hexdigest()}")
            print(f"SHA-256:  {hashlib.sha256(password.encode()).hexdigest()}")

def main():
    """Main password cracking simulation"""
    print("\n" + "="*60)
    print("EDUCATIONAL PASSWORD CRACKING SIMULATOR")
    print("="*60)
    print("\n⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️")
    print("This demonstrates why strong passwords are important\n")
    
    cracker = PasswordCracker()
    
    while True:
        print("\nOptions:")
        print("1. Create Test Password Database")
        print("2. Run Dictionary Attack")
        print("3. Hash Calculator Tool")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ")
        
        if choice == '1':
            cracker.create_password_file()
        elif choice == '2':
            cracker.dictionary_attack()
        elif choice == '3':
            cracker.hash_calculator()
        elif choice == '4':
            print("[*] Exiting...")
            break
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()
