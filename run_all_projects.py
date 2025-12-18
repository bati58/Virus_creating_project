#!/usr/bin/env python3
"""
MASTER SCRIPT - Run All Lab Projects
"""

import os
import sys
import subprocess
import time

def run_task3():
    """Run Task 3: Virus and Antivirus"""
    print("\n" + "="*70)
    print("TASK 3: VIRUS & ANTIVIRUS")
    print("="*70)
    
    os.chdir("Task3_Virus_Antivirus")
    
    print("\n1. Creating test files...")
    os.system("echo 'print(\"Clean file\")' > clean_test.py")
    os.system("echo 'print(\"Another clean file\")' > another_test.py")
    
    print("2. Running virus simulation...")
    os.system("python3 virus.py")
    
    input("\nPress Enter to run antivirus...")
    
    print("3. Running antivirus scan...")
    os.system("python3 antivirus.py")
    
    os.chdir("..")
    
    print("\n✅ Task 3 Complete!")
    print("Check Task3_Virus_Antivirus folder for results")

def run_task1():
    """Run Task 1: Attacks"""
    print("\n" + "="*70)
    print("TASK 1: SECURITY ATTACKS")
    print("="*70)
    
    print("\nAttack 1: Password Cracking Simulation")
    os.chdir("Task1_Attacks/password_cracking")
    os.system("python3 password_cracker.py")
    os.chdir("../..")
    
    input("\nPress Enter for Attack 2...")
    
    print("\nAttack 2: ARP Spoofing Simulation")
    os.chdir("Task1_Attacks/arp_spoofing")
    os.system("python3 arp_spoof_simulator.py")
    os.chdir("../..")
    
    print("\n✅ Task 1 Complete!")

def run_task2():
    """Run Task 2: Penetration Testing"""
    print("\n" + "="*70)
    print("TASK 2: PENETRATION TESTING")
    print("="*70)
    
    print("\nTool 1: Nmap Network Scanner")
    os.chdir("Task2_Penetration/nmap_scan")
    os.system("python3 nmap_simulator.py")
    os.chdir("../..")
    
    input("\nPress Enter for Tool 2...")
    
    print("\nTool 2: Nikto Web Vulnerability Scanner")
    os.chdir("Task2_Penetration/nikto_scan")
    os.system("python3 nikto_simulator.py")
    os.chdir("../..")
    
    print("\n✅ Task 2 Complete!")

def check_requirements():
    """Check if required tools are installed"""
    print("\n" + "="*70)
    print("CHECKING REQUIREMENTS")
    print("="*70)
    
    requirements = [
        ("Python 3", "python3 --version", True),
        ("Pip", "python3 -m pip --version", True),
    ]
    
    all_ok = True
    for name, command, required in requirements:
        try:
            result = subprocess.run(command, shell=True, 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ {name}: Installed")
                if name == "Python 3":
                    print(f"   Version: {result.stdout.strip()}")
            else:
                if required:
                    print(f"❌ {name}: Missing (Required)")
                    all_ok = False
                else:
                    print(f"⚠️  {name}: Missing (Optional)")
        except:
            if required:
                print(f"❌ {name}: Check failed")
                all_ok = False
    
    return all_ok

def create_report_template():
    """Create lab report template"""
    report = """# Computer Security Lab Project Report

## Student Information
- **Name:** [Your Name]
- **Student ID:** [Your ID]
- **Course:** Computer System Security
- **Date:** [Submission Date]

---

## Task 1: Security Attacks

### 1.1 Password Cracking Simulation

**Objective:** Demonstrate dictionary attack using weak passwords.

**Procedure:**
1. Created test password database with MD5 hashes
2. Used dictionary of common passwords
3. Compared hashes to crack passwords

**Results:**
[Include screenshots from password_cracking folder]

**Files Created:**
- password_database.txt
- cracking_results.txt
- password_cracker.py

### 1.2 ARP Spoofing Simulation

**Objective:** Demonstrate Man-in-the-Middle attack via ARP cache poisoning.

**Procedure:**
1. Simulated network with multiple devices
2. Demonstrated ARP table poisoning
3. Showed traffic interception capabilities

**Results:**
[Include screenshots from arp_spoofing folder]

**Files Created:**
- arp_spoof_simulator.py
- arp_spoofing_demo.txt

---

## Task 2: Penetration Testing Tools

### 2.1 Nmap Network Scanner

**Objective:** Perform network reconnaissance and vulnerability assessment.

**Procedure:**
1. Host discovery scan
2. Port scanning and service detection
3. OS fingerprinting
4. Vulnerability identification

**Results:**
[Include screenshots from nmap_scan folder]

**Files Created:**
- nmap_simulator.py
- nmap_scan_report_[timestamp].txt
- real_nmap_scan.txt (if nmap installed)

### 2.2 Nikto Web Vulnerability Scanner

**Objective:** Identify web application security vulnerabilities.

**Procedure:**
1. Scanned web server for common vulnerabilities
2. Identified XSS, SQLi, and misconfiguration issues
3. Generated risk assessment report

**Results:**
[Include screenshots from nikto_scan folder]

**Files Created:**
- nikto_simulator.py
- nikto_scan_report.html
- real_nikto_scan.txt (if nikto installed)

---

## Task 3: Virus and Antivirus Development

### 3.1 Educational Virus Program

**Objective:** Create a harmless virus demonstrating replication techniques.

**Features:**
- Self-replication to other Python files
- Harmless payload creation
- Educational message display

**Code Structure:**
[Brief explanation of virus.py code]

### 3.2 Educational Antivirus Program

**Objective:** Develop antivirus to detect and remove the educational virus.

**Features:**
- Signature-based detection
- File cleaning capabilities
- Scan logging and reporting

**Code Structure:**
[Brief explanation of antivirus.py code]

**Testing Results:**
[Include screenshots showing detection and cleaning]

---

## Ethical Considerations

All activities in this lab were conducted in controlled, isolated environments targeting only systems and applications owned by the student. No real networks, systems, or unauthorized resources were accessed or attacked.

1. **Authorization:** All testing was self-directed on personal equipment
2. **Isolation:** All activities performed in isolated directories
3. **Education:** Tools demonstrated concepts without causing harm
4. **Compliance:** Followed academic integrity and ethical guidelines

---

## Challenges and Learnings

### Challenges:
1. Simulating network attacks without actual network access
2. Creating realistic demonstrations within ethical boundaries
3. Ensuring code safety while demonstrating malicious techniques

### Learnings:
1. Importance of strong passwords and encryption
2. Network security vulnerabilities and protections
3. Virus detection mechanisms
4. Ethical hacking principles

---

## Conclusion

This lab project successfully demonstrated key computer security concepts including attack methodologies, penetration testing tools, and malware/antimalware development. The simulations provided practical understanding while maintaining ethical standards and legal compliance.

**Key Takeaways:**
- Security requires proactive measures
- Understanding attacks is crucial for defense
- Ethical practices are fundamental in security work
- Continuous learning is essential in cybersecurity

---
## Appendices

### Appendix A: Source Code
All source code is available in the respective task folders.

### Appendix B: Screenshots
See attached screenshots demonstrating each task's execution and results.

### Appendix C: References
1. Course materials and slides
2. Python documentation
3. Security tool documentation (Nmap, Nikto)
4. Ethical hacking guidelines
"""
    
    with open("Lab_Report_Template.md", "w") as f:
        f.write(report)
    
    print("\n[+] Lab report template created: Lab_Report_Template.md")

def main():
    """Main control panel"""
    print("\n" + "="*70)
    print("COMPUTER SECURITY LAB PROJECT - COMPLETE SUITE")
    print("="*70)
    print("\n⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️")
    print("All activities are simulations in controlled environments\n")
    
    # Check requirements
    if not check_requirements():
        print("\n❌ Some requirements missing. Install them first.")
        sys.exit(1)
    
    while True:
        print("\n" + "="*70)
        print("MAIN MENU")
        print("="*70)
        print("\nSelect Task to Run:")
        print("1. Run Task 3: Virus & Antivirus (Start Here)")
        print("2. Run Task 1: Security Attacks")
        print("3. Run Task 2: Penetration Testing")
        print("4. Run ALL Tasks in Sequence")
        print("5. Create Lab Report Template")
        print("6. Open Project Folder")
        print("7. Exit")
        
        choice = input("\nSelect option (1-7): ")
        
        if choice == '1':
            run_task3()
        elif choice == '2':
            run_task1()
        elif choice == '3':
            run_task2()
        elif choice == '4':
            print("\nRunning ALL tasks in sequence...")
            run_task3()
            run_task1()
            run_task2()
            print("\n" + "="*70)
            print("ALL TASKS COMPLETE!")
            print("="*70)
        elif choice == '5':
            create_report_template()
        elif choice == '6':
            project_path = os.path.abspath(".")
            print(f"\nProject location: {project_path}")
            if sys.platform == "darwin":  # macOS
                os.system(f"open '{project_path}'")
            elif sys.platform == "win32":  # Windows
                os.system(f"explorer '{project_path}'")
            else:  # Linux
                os.system(f"xdg-open '{project_path}'")
        elif choice == '7':
            print("\nThank you for using the Lab Project Suite!")
            print("Remember to submit your work and documentation.")
            break
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    # Ensure we're in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
