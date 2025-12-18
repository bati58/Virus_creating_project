#!/usr/bin/env python3
"""
Simple Educational Antivirus
Detects and removes the educational virus
"""

import os
import sys
import hashlib
import time

VIRUS_SIGNATURE = "VIRUS_SIGNATURE:EDU-2024-LEGIT"
SCAN_LOG = "antivirus_scan_log.txt"

class SimpleAntivirus:
    def __init__(self):
        self.infected_files = []
        self.cleaned_files = []
        self.scan_time = 0
        
    def log_scan(self, message):
        """Log scan activity"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        with open(SCAN_LOG, 'a') as log_file:
            log_file.write(log_entry)
        
        print(message)
    
    def calculate_hash(self, filepath):
        """Calculate MD5 hash of a file"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.md5()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except:
            return None
    
    def scan_file(self, filepath):
        """Scan single file for virus signature"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                if VIRUS_SIGNATURE in content:
                    file_hash = self.calculate_hash(filepath)
                    return {
                        'infected': True,
                        'filepath': filepath,
                        'hash': file_hash,
                        'size': os.path.getsize(filepath)
                    }
        except Exception as e:
            self.log_scan(f"[-] Error scanning {filepath}: {e}")
        
        return {'infected': False, 'filepath': filepath}
    
    def scan_directory(self, directory='.'):
        """Scan all Python files in directory"""
        start_time = time.time()
        self.log_scan(f"[*] Starting antivirus scan in: {os.path.abspath(directory)}")
        
        scan_count = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    result = self.scan_file(filepath)
                    
                    scan_count += 1
                    if result['infected']:
                        self.infected_files.append(result)
                        self.log_scan(f"[!] INFECTED: {filepath}")
                        self.log_scan(f"    Hash: {result['hash']}")
                        self.log_scan(f"    Size: {result['size']} bytes")
        
        self.scan_time = time.time() - start_time
        
        # Create summary report
        report = self.create_report(scan_count)
        self.log_scan(report)
        
        return self.infected_files
    
    def clean_file(self, filepath):
        """Remove virus code from infected file"""
        try:
            # Backup file before cleaning
            backup_path = filepath + ".infected_backup"
            os.system(f"cp '{filepath}' '{backup_path}'")
            
            # Read file content
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            # Find and remove infected lines
            clean_lines = []
            skip_next_n_lines = 0
            infected_found = False
            
            for line in lines:
                if VIRUS_SIGNATURE in line:
                    infected_found = True
                    skip_next_n_lines = 150  # Approximate virus code length
                    continue
                
                if skip_next_n_lines > 0:
                    skip_next_n_lines -= 1
                    continue
                
                clean_lines.append(line)
            
            if infected_found:
                # Write cleaned content
                with open(filepath, 'w') as f:
                    f.writelines(clean_lines)
                
                self.cleaned_files.append(filepath)
                self.log_scan(f"[+] Cleaned: {filepath}")
                return True
            else:
                os.remove(backup_path)
                
        except Exception as e:
            self.log_scan(f"[-] Error cleaning {filepath}: {e}")
        
        return False
    
    def clean_all_infected(self):
        """Clean all detected infections"""
        if not self.infected_files:
            self.log_scan("[*] No infected files to clean")
            return
        
        self.log_scan(f"[*] Cleaning {len(self.infected_files)} infected files...")
        
        cleaned_count = 0
        for infected in self.infected_files:
            if self.clean_file(infected['filepath']):
                cleaned_count += 1
        
        self.log_scan(f"[+] Successfully cleaned {cleaned_count}/{len(self.infected_files)} files")
    
    def create_report(self, files_scanned):
        """Create scan summary report"""
        report = "\n" + "="*60
        report += "\nANTIVIRUS SCAN REPORT\n"
        report += "="*60 + "\n"
        
        report += f"Scan Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Directory:          {os.path.abspath('.')}\n"
        report += f"Files Scanned:      {files_scanned}\n"
        report += f"Infected Files:     {len(self.infected_files)}\n"
        report += f"Scan Duration:      {self.scan_time:.2f} seconds\n"
        
        if self.infected_files:
            report += "\n📁 INFECTED FILES:\n"
            for i, infected in enumerate(self.infected_files, 1):
                report += f"\n{i}. {infected['filepath']}\n"
                report += f"   Hash: {infected['hash']}\n"
                report += f"   Size: {infected['size']} bytes\n"
        else:
            report += "\n✅ SYSTEM CLEAN: No infections found!\n"
        
        report += "\n" + "="*60
        
        # Save report to file
        with open("antivirus_report.txt", 'w') as report_file:
            report_file.write(report)
        
        return report
    
    def quick_scan(self):
        """Quick scan of current directory"""
        print("\n🔍 QUICK SCAN MODE")
        print("="*40)
        
        # Create test files for demonstration
        self.create_test_files()
        
        # Run scan
        infected = self.scan_directory('.')
        
        if infected:
            response = input("\nDo you want to clean infected files? (y/n): ")
            if response.lower() == 'y':
                self.clean_all_infected()
        
        print(f"\n📄 Detailed report saved to: antivirus_report.txt")
        print(f"📝 Activity log saved to: {SCAN_LOG}")
    
    def create_test_files(self):
        """Create test Python files for demonstration"""
        test_files = [
            ("clean_program.py", "print('This is a clean Python program')\n# No virus here\n"),
            ("calculator.py", "def add(a, b):\n    return a + b\n\nprint(add(5, 3))\n"),
            ("hello_world.py", "print('Hello, World!')\n")
        ]
        
        for filename, content in test_files:
            if not os.path.exists(filename):
                with open(filename, 'w') as f:
                    f.write(content)
                print(f"[+] Created test file: {filename}")

def main():
    """Main antivirus program"""
    print("\n" + "="*60)
    print("SIMPLE EDUCATIONAL ANTIVIRUS")
    print("="*60)
    print("\nOptions:")
    print("1. Quick Scan (Current Directory)")
    print("2. Custom Directory Scan")
    print("3. Scan and Auto-Clean")
    print("4. Exit")
    
    try:
        choice = input("\nSelect option (1-4): ")
        
        antivirus = SimpleAntivirus()
        
        if choice == '1':
            antivirus.quick_scan()
        elif choice == '2':
            directory = input("Enter directory path to scan: ")
            if os.path.exists(directory):
                antivirus.scan_directory(directory)
            else:
                print("[-] Directory does not exist")
        elif choice == '3':
            antivirus.scan_directory('.')
            if antivirus.infected_files:
                antivirus.clean_all_infected()
        elif choice == '4':
            print("[*] Exiting...")
            sys.exit(0)
        else:
            print("[-] Invalid choice")
    
    except KeyboardInterrupt:
        print("\n\n[*] Scan interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
