Folder for Computer Security Lab Project
Created: Wed Dec 10 09:42:55 AM EAT 2025
cd ~/Desktop/Lab_Project/Task2_Penetration

# Nmap
cd nmap_scan
nmap -sV 127.0.0.1

# Nikto (needs web server)
python3 -m http.server 8080 &
nikto -h http://127.0.0.1:8080
