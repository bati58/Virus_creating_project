#!/usr/bin/env python3
"""
Nmap Network Scanner Simulation
Demonstrates network reconnaissance concepts
"""

import socket
import subprocess
import time

class NmapSimulator:
    def __init__(self):
        self.target_ip = "127.0.0.1"  # Localhost for safe testing
        self.scan_results = {}
    
    def host_discovery(self):
        """Simulate host discovery scan"""
        print("\n[*] Starting Host Discovery Scan...")
        print("[*] Scanning network 192.168.1.0/24")
        
        # Simulate finding hosts
        hosts = [
            ("192.168.1.1", "Router", "Online"),
            ("192.168.1.100", "Windows-PC", "Online"),
            ("192.168.1.101", "Linux-Server", "Online"),
            ("192.168.1.150", "Network-Printer", "Online"),
            ("192.168.1.200", "Web-Server", "Online")
        ]
        
        print("\nDiscovered Hosts:")
        print("-" * 50)
        print("IP Address        Hostname         Status")
        print("-" * 50)
        
        for ip, hostname, status in hosts:
            print(f"{ip:15} {hostname:15} {status}")
            time.sleep(0.5)
        
        self.scan_results['hosts'] = hosts
        return hosts
    
    def port_scan(self, target_ip=None):
        """Simulate port scanning"""
        if target_ip is None:
            target_ip = self.target_ip
        
        print(f"\n[*] Starting Port Scan on {target_ip}...")
        
        # Common ports and services
        common_ports = [
            (21, "FTP", "open", "vsftpd 3.0.3"),
            (22, "SSH", "open", "OpenSSH 7.9"),
            (23, "Telnet", "closed", "-"),
            (25, "SMTP", "open", "Postfix"),
            (53, "DNS", "open", "BIND 9.11"),
            (80, "HTTP", "open", "Apache 2.4.41"),
            (110, "POP3", "filtered", "-"),
            (139, "NetBIOS", "open", "Samba 4.10"),
            (443, "HTTPS", "open", "Apache 2.4.41"),
            (445, "SMB", "open", "Samba 4.10"),
            (3306, "MySQL", "open", "MySQL 8.0"),
            (3389, "RDP", "closed", "-"),
            (8080, "HTTP-Proxy", "open", "Apache Tomcat")
        ]
        
        print("\nPORT     STATE SERVICE    VERSION")
        print("-" * 40)
        
        open_ports = []
        for port, service, state, version in common_ports:
            print(f"{port:5}/tcp {state:7} {service:10} {version}")
            if state == "open":
                open_ports.append((port, service, version))
            time.sleep(0.3)
        
        self.scan_results['ports'] = open_ports
        return open_ports
    
    def os_detection(self):
        """Simulate OS detection"""
        print("\n[*] Starting OS Detection...")
        print("[*] Analyzing network stack...")
        time.sleep(2)
        
        os_info = {
            "Target": "192.168.1.100",
            "OS": "Linux 4.15-5.4",
            "Details": "Ubuntu 18.04/20.04",
            "Accuracy": "96%"
        }
        
        print("\nOS Detection Results:")
        print("-" * 30)
        for key, value in os_info.items():
            print(f"{key:10}: {value}")
        
        self.scan_results['os'] = os_info
        return os_info
    
    def vulnerability_scan(self):
        """Simulate vulnerability scanning"""
        print("\n[*] Starting Vulnerability Scan...")
        print("[*] Checking for known vulnerabilities...")
        
        vulnerabilities = [
            ("CVE-2021-41773", "Apache HTTP Server Path Traversal", "HIGH", "Update to 2.4.51"),
            ("CVE-2021-44228", "Log4Shell - Log4j RCE", "CRITICAL", "Update Log4j to 2.17.0"),
            ("CVE-2021-3449", "OpenSSL Denial of Service", "MEDIUM", "Update OpenSSL"),
            ("MS17-010", "EternalBlue SMB Vulnerability", "CRITICAL", "Install security updates"),
            ("CVE-2019-0708", "BlueKeep RDP Vulnerability", "CRITICAL", "Update Windows")
        ]
        
        print("\nVulnerabilities Found:")
        print("-" * 70)
        print("CVE ID          Description                  Severity    Solution")
        print("-" * 70)
        
        for cve, desc, severity, solution in vulnerabilities:
            print(f"{cve:15} {desc:25} {severity:10} {solution}")
            time.sleep(0.5)
        
        self.scan_results['vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def generate_report(self):
        """Generate scan report"""
        print("\n[*] Generating Scan Report...")
        
        report = "\n" + "="*60
        report += "\nNMAP SCAN REPORT\n"
        report += "="*60 + "\n"
        
        report += f"\nScan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if 'hosts' in self.scan_results:
            report += "\n📡 DISCOVERED HOSTS:\n"
            for ip, hostname, status in self.scan_results['hosts']:
                report += f"{ip} ({hostname}) - {status}\n"
        
        if 'ports' in self.scan_results:
            report += "\n🔓 OPEN PORTS:\n"
            for port, service, version in self.scan_results['ports']:
                report += f"Port {port}/tcp: {service} ({version})\n"
        
        if 'os' in self.scan_results:
            report += "\n💻 OS DETECTION:\n"
            for key, value in self.scan_results['os'].items():
                report += f"{key}: {value}\n"
        
        if 'vulnerabilities' in self.scan_results:
            report += "\n⚠️  VULNERABILITIES:\n"
            for cve, desc, severity, _ in self.scan_results['vulnerabilities']:
                report += f"{cve}: {desc} [{severity}]\n"
        
        report += "\n" + "="*60
        report += "\nRECOMMENDATIONS:\n"
        report += "1. Close unnecessary ports\n"
        report += "2. Update software regularly\n"
        report += "3. Use firewalls and IDS/IPS\n"
        report += "4. Regular security audits\n"
        report += "="*60
        
        # Save report
        filename = f"nmap_scan_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(report)
        
        print(f"[+] Report saved to {filename}")
        print(report)
        
        return filename
    
    def real_nmap_check(self):
        """Check if real nmap is installed and try a safe scan"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Nmap is installed on your system!")
                print(f"Version: {result.stdout.split()[2]}")
                
                # Ask if user wants to do a real local scan
                response = input("\nDo you want to run a real nmap scan on localhost? (y/n): ")
                if response.lower() == 'y':
                    print("\n[*] Running: nmap -sS -sV 127.0.0.1")
                    print("[*] This may take a moment...\n")
                    
                    real_scan = subprocess.run(['nmap', '-sS', '-sV', '127.0.0.1'],
                                             capture_output=True, text=True)
                    print(real_scan.stdout)
                    
                    # Save real results
                    with open("real_nmap_scan.txt", "w") as f:
                        f.write(real_scan.stdout)
                    print("[+] Real scan results saved to real_nmap_scan.txt")
                
                return True
        except FileNotFoundError:
            print("[-] Nmap not found. Running in simulation mode only.")
            print("[*] To install nmap: sudo apt install nmap")
            return False
    
    def run_complete_scan(self):
        """Run complete scanning simulation"""
        print("\n" + "="*60)
        print("COMPLETE NETWORK SCANNING SIMULATION")
        print("="*60)
        
        self.host_discovery()
        input("\nPress Enter to continue to port scan...")
        
        self.port_scan()
        input("\nPress Enter to continue to OS detection...")
        
        self.os_detection()
        input("\nPress Enter to continue to vulnerability scan...")
        
        self.vulnerability_scan()
        input("\nPress Enter to generate report...")
        
        self.generate_report()
        
        # Check for real nmap
        self.real_nmap_check()

def main():
    """Main Nmap simulator"""
    scanner = NmapSimulator()
    
    print("\n" + "="*60)
    print("EDUCATIONAL NMAP SCANNER SIMULATOR")
    print("="*60)
    print("\n⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️")
    print("Scan only systems you own or have permission to scan\n")
    
    while True:
        print("\nScan Options:")
        print("1. Run Complete Scan Simulation")
        print("2. Host Discovery Only")
        print("3. Port Scan Only")
        print("4. OS Detection")
        print("5. Vulnerability Scan")
        print("6. Check for Real Nmap")
        print("7. Exit")
        
        choice = input("\nSelect option (1-7): ")
        
        if choice == '1':
            scanner.run_complete_scan()
        elif choice == '2':
            scanner.host_discovery()
        elif choice == '3':
            target = input("Enter target IP (default 127.0.0.1): ")
            scanner.port_scan(target if target else None)
        elif choice == '4':
            scanner.os_detection()
        elif choice == '5':
            scanner.vulnerability_scan()
        elif choice == '6':
            scanner.real_nmap_check()
        elif choice == '7':
            print("[*] Exiting...")
            break
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()
