#!/usr/bin/env python3
"""
ARP Spoofing Simulation (Educational)
Demonstrates Man-in-the-Middle attack concepts
"""

import os
import time

class ARPSpoofSimulator:
    def __init__(self):
        self.network_devices = {
            "Router": "192.168.1.1",
            "Victim_PC": "192.168.1.100",
            "Attacker_PC": "192.168.1.50",
            "Server": "192.168.1.200"
        }
        
        self.arp_table = {}
        self.spoofing_active = False
    
    def display_network(self):
        """Display current network topology"""
        print("\n" + "="*60)
        print("NETWORK TOPOLOGY SIMULATION")
        print("="*60)
        
        for device, ip in self.network_devices.items():
            print(f"{device:15} -> {ip}")
        
        print("\nARP Table (Before Attack):")
        print("IP Address       MAC Address")
        print("-"*30)
        
        # Simulated ARP table
        arp_entries = {
            "192.168.1.1": "00:1A:2B:3C:4D:5E",
            "192.168.1.100": "AA:BB:CC:DD:EE:FF",
            "192.168.1.50": "11:22:33:44:55:66",
            "192.168.1.200": "66:77:88:99:AA:BB"
        }
        
        for ip, mac in arp_entries.items():
            print(f"{ip:15} {mac}")
            self.arp_table[ip] = mac
    
    def demonstrate_arp_spoofing(self):
        """Demonstrate ARP spoofing attack"""
        print("\n" + "="*60)
        print("ARP SPOOFING ATTACK DEMONSTRATION")
        print("="*60)
        
        print("\n[*] Step 1: Normal Communication")
        print("    Victim (192.168.1.100) wants to talk to Router (192.168.1.1)")
        print("    Victim checks ARP table: Router -> 00:1A:2B:3C:4D:5E")
        print("    Traffic flows directly between Victim and Router")
        
        time.sleep(2)
        
        print("\n[*] Step 2: Attacker initiates ARP Spoofing")
        print("    Attacker sends fake ARP replies to Victim:")
        print("    'Router (192.168.1.1) is at 11:22:33:44:55:66 (Attacker's MAC)'")
        print("    And to Router:")
        print("    'Victim (192.168.1.100) is at 11:22:33:44:55:66 (Attacker's MAC)'")
        
        self.spoofing_active = True
        
        time.sleep(2)
        
        print("\n[*] Step 3: ARP Table Poisoning Complete")
        print("    Victim's ARP Table Now:")
        print("    192.168.1.1 -> 11:22:33:44:55:66 (WRONG - Attacker's MAC)")
        print("    Router's ARP Table Now:")
        print("    192.168.1.100 -> 11:22:33:44:55:66 (WRONG - Attacker's MAC)")
        
        time.sleep(2)
        
        print("\n[*] Step 4: Man-in-the-Middle Established")
        print("    All traffic between Victim and Router now goes through Attacker")
        print("    Attacker can:")
        print("    1. Monitor traffic (Sniffing)")
        print("    2. Modify traffic (Injection)")
        print("    3. Block traffic (DoS)")
    
    def packet_sniffing_demo(self):
        """Demonstrate packet sniffing"""
        print("\n" + "="*60)
        print("PACKET SNIFFING DEMONSTRATION")
        print("="*60)
        
        print("\n[*] Attacker is now intercepting traffic...")
        print("[*] Captured packets:")
        
        # Simulated captured packets
        packets = [
            ("HTTP Request", "GET /login.html HTTP/1.1"),
            ("Email", "Subject: Project Update"),
            ("FTP Credentials", "USER: admin PASS: secret123"),
            ("HTTP Response", "Set-Cookie: session=abc123xyz"),
            ("DNS Query", "google.com -> 8.8.8.8")
        ]
        
        for i, (packet_type, content) in enumerate(packets, 1):
            print(f"\nPacket #{i}: {packet_type}")
            print(f"Content: {content}")
            time.sleep(1)
        
        print("\n[*] This demonstrates why encryption (HTTPS/SSL) is important!")
    
    def prevention_methods(self):
        """Show ARP spoofing prevention"""
        print("\n" + "="*60)
        print("ARP SPOOFING PREVENTION METHODS")
        print("="*60)
        
        prevention_techniques = [
            ("Static ARP Entries", 
             "Manually configure ARP table entries\n   Prevents dynamic updates but not scalable"),
            
            ("ARP Monitoring Tools", 
             "Tools like Arpwatch monitor ARP traffic\n   Alert on suspicious changes"),
            
            ("Network Segmentation", 
             "Divide network into segments/VLANs\n   Limit impact of attacks"),
            
            ("Encryption", 
             "Use HTTPS, SSH, VPNs\n   Even if intercepted, data is encrypted"),
            
            ("Port Security", 
             "Switch features to limit MAC addresses per port\n   Prevents MAC flooding attacks")
        ]
        
        for i, (method, description) in enumerate(prevention_techniques, 1):
            print(f"\n{i}. {method}:")
            print(f"   {description}")
    
    def run_simulation(self):
        """Run complete ARP spoofing simulation"""
        print("\n" + "="*60)
        print("COMPLETE ARP SPOOFING SIMULATION")
        print("="*60)
        
        self.display_network()
        input("\nPress Enter to continue to attack demonstration...")
        
        self.demonstrate_arp_spoofing()
        input("\nPress Enter to see intercepted traffic...")
        
        self.packet_sniffing_demo()
        input("\nPress Enter to learn about prevention...")
        
        self.prevention_methods()
        
        # Save demonstration log
        self.save_demonstration_log()
    
    def save_demonstration_log(self):
        """Save simulation details to file"""
        with open("arp_spoofing_demo.txt", "w") as f:
            f.write("ARP Spoofing Demonstration Log\n")
            f.write("="*40 + "\n\n")
            f.write("Network Devices:\n")
            for device, ip in self.network_devices.items():
                f.write(f"{device}: {ip}\n")
            
            f.write("\nAttack Summary:\n")
            f.write("1. Attacker sends fake ARP replies\n")
            f.write("2. Victim and Router update ARP tables incorrectly\n")
            f.write("3. Traffic rerouted through Attacker\n")
            f.write("4. Attacker becomes Man-in-the-Middle\n")
            
            f.write("\nPrevention Methods:\n")
            f.write("- Use static ARP entries\n")
            f.write("- Implement ARP monitoring\n")
            f.write("- Enable port security on switches\n")
            f.write("- Use encrypted protocols (HTTPS, VPN)\n")
        
        print("\n[+] Demonstration log saved to arp_spoofing_demo.txt")

def main():
    """Main ARP spoofing simulation"""
    simulator = ARPSpoofSimulator()
    
    print("\n" + "="*60)
    print("EDUCATIONAL ARP SPOOFING SIMULATOR")
    print("="*60)
    print("\n⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️")
    print("This demonstrates network security concepts\n")
    
    while True:
        print("\nOptions:")
        print("1. Run Complete Simulation")
        print("2. View Network Topology")
        print("3. Demonstrate ARP Spoofing")
        print("4. Show Prevention Methods")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ")
        
        if choice == '1':
            simulator.run_simulation()
        elif choice == '2':
            simulator.display_network()
        elif choice == '3':
            simulator.demonstrate_arp_spoofing()
        elif choice == '4':
            simulator.prevention_methods()
        elif choice == '5':
            print("[*] Exiting...")
            break
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()
