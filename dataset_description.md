# Source 1: UNSW-NB15 Dataset
https://research.unsw.edu.au/projects/unsw-nb15-dataset 
The UNSW-NB15 dataset has nine attack types including Exploits, Backdoors, Shellcode, and Worms. 
CVS Files → Training and Testing Sets → UNSW_NB15_training-set.csv
## Zero-Day Scenarios:
    (1) WannaCry: these are flat, labeled CSVs with 49 features per flow, attack category labeled (filter for Exploits or Worms)
    (2) Data Theft (FTP/SSH): In the downloaded CSV, filter the attack_cat column for Backdoor or Exploits. Additionally, the proto column and dport (destination port 21 = FTP, 22 = SCP) can narrow to exfiltration-style flows.
    (3) ShellShock: Filter attack_cat = Shellcode. You can also cross-reference port 80 (dport = 80) flows to isolate Apache-targeted shellcode injection events.
    (4) Nelcat Backdoor: Filter attack_cat = Backdoor. Flows with unusual destination ports (non-standard, high-numbered ports) in this category are most representative of Netcat listeners.
    (5) Passwd-gzip-scp: filter attack_cat = Backdoor, proto = tcp, dport = 22. These flows represent SSH-based data transfer sessions consistent with SCP exfiltration of sensitive files.
#Source 2: CICIDS2017
https://www.unb.ca/cic/datasets/ids-2017.html 
The CICIDS2017 dataset includes full packet payloads in PCAP format and labeled flows as CSVs, capturing realistic background traffic alongside attacks including infiltration scenarios.
CSVs → MachineLearningCSV.zip → Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
## Zero-Day Scenarios:
    (1) Phishing (Excel/Java): filter the Label column for Infiltration or Web Attack – Brute Force
    (2) Cheating Student: Filter Label = Web Attack – Brute Force or Infiltration — these capture unauthorized HTTP GET/POST to web-hosted files, analogous to downloading/uploading modified content from an Apache server
