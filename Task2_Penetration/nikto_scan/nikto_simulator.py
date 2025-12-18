#!/usr/bin/env python3
"""
Nikto Web Vulnerability Scanner Simulation
Demonstrates web application security testing
"""

import time
import random

class NiktoSimulator:
    def __init__(self):
        self.target_url = "http://localhost"
        self.vulnerabilities = []
    
    def scan_web_server(self):
        """Simulate Nikto web server scan"""
        print(f"\n[*] Starting Nikto scan on: {self.target_url}")
        print("[*] This may take a few moments...")
        time.sleep(2)
        
        # Simulated scan progress
        steps = [
            ("Testing for HTTP methods", 85),
            ("Checking for default files", 92),
            ("Scanning for CGI directories", 78),
            ("Testing for XSS vulnerabilities", 65),
            ("Checking for SQL injection points", 71),
            ("Testing for server misconfigurations", 88),
            ("Looking for backup files", 94),
            ("Checking HTTP headers", 82)
        ]
        
        print("\nScan Progress:")
        for step, percent in steps:
            bar = "█" * (percent // 5) + "░" * (20 - (percent // 5))
            print(f"{step:35} [{bar}] {percent}%")
            time.sleep(0.5)
        
        print("\n[*] Scan complete!")
    
    def find_vulnerabilities(self):
        """Simulate finding web vulnerabilities"""
        print("\n" + "="*70)
        print("WEB VULNERABILITY FINDINGS")
        print("="*70)
        
        vulnerability_list = [
            {
                "id": "001",
                "type": "Information Disclosure",
                "severity": "LOW",
                "description": "Server banner reveals Apache/2.4.41 (Ubuntu)",
                "solution": "Hide server version in HTTP headers"
            },
            {
                "id": "002",
                "type": "XSS Vulnerability",
                "severity": "MEDIUM",
                "description": "Cross-site scripting in search parameter: ?q=<script>",
                "solution": "Implement input validation and output encoding"
            },
            {
                "id": "003",
                "type": "Directory Listing",
                "severity": "MEDIUM",
                "description": "Directory listing enabled on /images/",
                "solution": "Disable directory listing in server config"
            },
            {
                "id": "004",
                "type": "Missing Security Headers",
                "severity": "LOW",
                "description": "Missing X-Frame-Options, X-Content-Type-Options",
                "solution": "Add security headers to HTTP responses"
            },
            {
                "id": "005",
                "type": "Default Files Present",
                "severity": "INFO",
                "description": "Found /test.php, /phpinfo.php",
                "solution": "Remove default/test files from production"
            },
            {
                "id": "006",
                "type": "SQL Injection Possible",
                "severity": "HIGH",
                "description": "Parameter 'id' in /product.php vulnerable to SQLi",
                "solution": "Use parameterized queries and input validation"
            },
            {
                "id": "007",
                "type": "CSRF Vulnerability",
                "severity": "MEDIUM",
                "description": "Forms lack anti-CSRF tokens",
                "solution": "Implement CSRF tokens for all state-changing operations"
            }
        ]
        
        # Display vulnerabilities
        print("\nID  Severity  Type                     Description")
        print("-" * 70)
        
        for vuln in vulnerability_list:
            print(f"{vuln['id']:3} {vuln['severity']:8} {vuln['type']:24} {vuln['description'][:40]}...")
            time.sleep(0.3)
        
        self.vulnerabilities = vulnerability_list
        return vulnerability_list
    
    def detailed_vulnerability_report(self):
        """Show detailed vulnerability information"""
        if not self.vulnerabilities:
            print("[-] No vulnerabilities found. Run scan first.")
            return
        
        print("\n" + "="*70)
        print("DETAILED VULNERABILITY REPORT")
        print("="*70)
        
        for vuln in self.vulnerabilities:
            print(f"\n[{vuln['id']}] {vuln['type']} - {vuln['severity']} Severity")
            print(f"Description: {vuln['description']}")
            print(f"Solution: {vuln['solution']}")
            print(f"Risk: {'🔴' if vuln['severity'] == 'HIGH' else '🟡' if vuln['severity'] == 'MEDIUM' else '🟢'}")
            print("-" * 70)
            time.sleep(1)
    
    def risk_assessment(self):
        """Provide risk assessment"""
        print("\n" + "="*60)
        print("RISK ASSESSMENT SUMMARY")
        print("="*60)
        
        severities = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.vulnerabilities:
            severities[vuln["severity"]] += 1
        
        total = len(self.vulnerabilities)
        
        print(f"\nTotal Vulnerabilities: {total}")
        print(f"High Risk:    {severities['HIGH']} ({severities['HIGH']/total*100:.1f}%)")
        print(f"Medium Risk:  {severities['MEDIUM']} ({severities['MEDIUM']/total*100:.1f}%)")
        print(f"Low Risk:     {severities['LOW']} ({severities['LOW']/total*100:.1f}%)")
        print(f"Info:         {severities['INFO']} ({severities['INFO']/total*100:.1f}%)")
        
        # Overall risk rating
        if severities['HIGH'] > 0:
            rating = "CRITICAL 🚨"
        elif severities['MEDIUM'] > 2:
            rating = "HIGH ⚠️"
        elif severities['MEDIUM'] > 0:
            rating = "MEDIUM ⚠️"
        else:
            rating = "LOW ✅"
        
        print(f"\nOverall Risk: {rating}")
    
    def generate_html_report(self):
        """Generate HTML report"""
        if not self.vulnerabilities:
            print("[-] No vulnerabilities to report. Run scan first.")
            return
        
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Nikto Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .vulnerability { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        .high { border-left: 5px solid #e74c3c; }
        .medium { border-left: 5px solid #f39c12; }
        .low { border-left: 5px solid #3498db; }
        .info { border-left: 5px solid #2ecc71; }
        .severity { font-weight: bold; padding: 3px 8px; border-radius: 3px; }
        .high-sev { background: #e74c3c; color: white; }
        .medium-sev { background: #f39c12; color: white; }
        .low-sev { background: #3498db; color: white; }
        .info-sev { background: #2ecc71; color: white; }
    </style>
</head>
<body>
    <h1>Nikto Web Vulnerability Scan Report</h1>
    <p>Target: """ + self.target_url + """</p>
    <p>Scan Date: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
    <hr>
"""
        
        for vuln in self.vulnerabilities:
            severity_class = {
                "HIGH": "high-sev",
                "MEDIUM": "medium-sev", 
                "LOW": "low-sev",
                "INFO": "info-sev"
            }[vuln["severity"]]
            
            html += f"""
    <div class="vulnerability {vuln['severity'].lower()}">
        <h3>{vuln['type']}</h3>
        <span class="severity {severity_class}">{vuln['severity']}</span>
        <p><strong>Description:</strong> {vuln['description']}</p>
        <p><strong>Solution:</strong> {vuln['solution']}</p>
    </div>
"""
        
        html += """
</body>
</html>"""
        
        filename = "nikto_scan_report.html"
        with open(filename, "w") as f:
            f.write(html)
        
        print(f"\n[+] HTML report generated: {filename}")
        print(f"[+] Open {filename} in your browser to view the report")
        
        return filename
    
    def run_complete_scan(self):
        """Run complete Nikto simulation"""
        print("\n" + "="*60)
        print("NIKTO WEB VULNERABILITY SCANNER SIMULATION")
        print("="*60)
        
        self.scan_web_server()
        input("\nPress Enter to view findings...")
        
        self.find_vulnerabilities()
        input("\nPress Enter for detailed report...")
        
        self.detailed_vulnerability_report()
        input("\nPress Enter for risk assessment...")
        
        self.risk_assessment()
        input("\nPress Enter to generate HTML report...")
        
        self.generate_html_report()
        
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print("\nNext Steps:")
        print("1. Review all vulnerabilities")
        print("2. Prioritize HIGH severity issues")
        print("3. Implement recommended solutions")
        print("4. Rescan after fixes")
    
    def real_nikto_check(self):
        """Check if real Nikto is installed"""
        try:
            import subprocess
            result = subprocess.run(['nikto', '-Version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Nikto is installed on your system!")
                
                response = input("\nDo you want to run a real Nikto scan on localhost? (y/n): ")
                if response.lower() == 'y':
                    print("\n[*] Running: nikto -h http://localhost")
                    print("[*] This may take a few minutes...\n")
                    
                    # Run with timeout
                    real_scan = subprocess.run(['nikto', '-h', 'http://localhost', '-output', 'real_nikto_scan.txt'],
                                             capture_output=True, text=True, timeout=30)
                    print("Scan output saved to real_nikto_scan.txt")
                    
                    # Show part of output
                    with open("real_nikto_scan.txt", "r") as f:
                        lines = f.readlines()[:20]
                        print("\n".join(lines))
                
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("[-] Nikto not found or scan timed out.")
            print("[*] To install Nikto: sudo apt install nikto")
            return False

def main():
    """Main Nikto simulator"""
    scanner = NiktoSimulator()
    
    print("\n" + "="*60)
    print("EDUCATIONAL NIKTO WEB SCANNER SIMULATOR")
    print("="*60)
    print("\n⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️")
    print("Only scan websites you own or have permission to scan\n")
    
    while True:
        print("\nScan Options:")
        print("1. Run Complete Web Vulnerability Scan")
        print("2. Scan Web Server")
        print("3. Show Vulnerability Details")
        print("4. Generate Risk Assessment")
        print("5. Create HTML Report")
        print("6. Check for Real Nikto")
        print("7. Change Target URL")
        print("8. Exit")
        
        choice = input("\nSelect option (1-8): ")
        
        if choice == '1':
            scanner.run_complete_scan()
        elif choice == '2':
            scanner.scan_web_server()
            scanner.find_vulnerabilities()
        elif choice == '3':
            scanner.detailed_vulnerability_report()
        elif choice == '4':
            scanner.risk_assessment()
        elif choice == '5':
            scanner.generate_html_report()
        elif choice == '6':
            scanner.real_nikto_check()
        elif choice == '7':
            new_url = input("Enter new target URL: ")
            scanner.target_url = new_url
            print(f"[+] Target changed to: {new_url}")
        elif choice == '8':
            print("[*] Exiting...")
            break
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()
