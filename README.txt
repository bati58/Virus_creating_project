COMPUTER SECURITY LAB PROJECT SUBMISSION
========================================

This zip file contains all required work for the lab project:

STRUCTURE:
----------
Lab_Project/
├── Task1_Attacks/          # Password cracking & ARP spoofing
├── Task2_Penetration/      # Nmap & Nikto scans
├── Task3_Virus_Antivirus/  # Python virus & antivirus
├── Reports/               # Summary reports
├── Screenshots/           # Screenshots of execution
└── Lab_Project_Submission.zip (this file)

HOW TO VERIFY:
--------------
1. Extract the zip file
2. Check each folder for output files
3. View screenshots showing execution
4. Run python programs to see them work

NOTE: All work done ethically in Kali Linux VM
No real systems were attacked.

Student: [bati jano]
Date: $(date)


# 1. Go to project
cd ~/Desktop/Lab_Project

# 2. Test Task 3
cd Task3_Virus_Antivirus
python3 virus.py
# Take screenshot
python3 antivirus.py
# Type 'y' when asked, take screenshot
cd ..

# 3. Test Task 1
cd Task1_Attacks/password_cracking
python3 password_cracker.py
# Take screenshot
cd ../arp_spoofing
python3 arp_spoof_simulator.py
# Choose option 1, take screenshot
cd ../..

# 4. Test Task 2
cd Task2_Penetration/nmap_scan
python3 nmap_simulator.py
# Choose option 1, take screenshot
cd ../nikto_scan
python3 nikto_simulator.py
# Choose option 1, take screenshot
cd ../..

echo "🎉 ALL DONE! Check Screenshots folder."
