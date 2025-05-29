
 Cyber Threat Automation Toolkit

A collection of Python scripts designed to automate various tasks related to cyber threat intelligence, reconnaissance, analysis, and incident response. This toolkit aims to provide cybersecurity professionals and enthusiasts with handy utilities to streamline their workflows.

 🚩 Table of Contents

- [Overview](-overview)
- [Features](-features)
- [Tools Included](-tools-included)
  - [DNS Reconnaissance](dns-reconnaissance)
  - [Email Analysis](email-analysis)
  - [Network Analysis](network-analysis)
  - [Phishing Analysis](phishing-analysis)
  - [SIEM Integration](siem-integration)
  - [Vulnerability Scanning](vulnerability-scanning)
  - [Web Scraping](web-scraping)
- [Prerequisites](-prerequisites)
- [Installation](-installation)
- [Usage](-usage)
- [Contributing](-contributing)
- [License](-license)
- [Disclaimer](-disclaimer)

 🔭 Overview

This repository hosts a suite of scripts, each targeting a specific area of cybersecurity automation. These tools can be used independently for quick analysis or integrated into larger security workflows.

 ✨ Features

-   DNS Enumeration: Discover various DNS records for a target domain.
-   Email Header Analysis: Parse and analyze email headers for forensics.
-   Network Traffic Analysis: Sniff and analyze network packets (basic).
-   URL Phishing Detection: Analyze URLs for potential phishing indicators.
-   SIEM Event Forwarding: Send custom events to a Splunk HEC.
-   Vulnerability Scanning: Automate Nmap scans for network discovery and vulnerability assessment.
-   Threat Intel Scraping: Basic web scraper for threat intelligence feeds (template).

 🛠️ Tools Included

Below is a list of the scripts available in this toolkit, organized by their respective directories.

---

 1. DNS Reconnaissance (DNS-Recon/)

 dns_enum.py
    - Description: Performs DNS enumeration for a given domain, retrieving common record types (A, AAAA, MX, NS, SOA, TXT, CNAME).
    - Dependencies: dnspython
    - Usage:
    
      python DNS-Recon/dns_enum.py <domain_name>
    
    - Example:

      python DNS-Recon/dns_enum.py example.com
   

---

 2. Email Analysis (Email-Analysis/)

 analyze_email_headers.py
    - Description: Parses and analyzes email headers from an .eml file. It extracts key information like From, To, Subject, Date, Received path, and checks for SPF, DKIM, and DMARC records if present in headers.
    - Dependencies: (Python built-in email module)
    - Usage:
      
      python Email-Analysis/analyze_email_headers.py <path_to_eml_file>
      
    - Example:
      
      python Email-Analysis/analyze_email_headers.py suspicious_email.eml
      

---

 3. Network Analysis (Network-Analysis/)

 network_traffic_analyzer.py
    - Description: A basic network traffic sniffer and analyzer. Captures packets on a specified interface and provides a summary of protocols and source/destination IP addresses.
    - Dependencies: scapy
    - Note: This script typically requires root/administrator privileges to capture network packets.
    - Usage:
      
      sudo python Network-Analysis/network_traffic_analyzer.py <network_interface> [packet_count]
      
    - Example:
    
      sudo python Network-Analysis/network_traffic_analyzer.py eth0 100
    

---

 4. Phishing Analysis (Phishing-Analysis/)

 url_analyzer.py
    - Description: Analyzes a given URL for potential phishing indicators. It checks WHOIS information, SSL certificate details, keywords in the content, and performs a Levenshtein distance check against a list of common legitimate domains to detect typosquatting.
    - Dependencies: requests, beautifulsoup4, python-whois, python-Levenshtein
    - Usage:
     
      python Phishing-Analysis/url_analyzer.py <url_to_analyze>
    
    - Example:
     
      python Phishing-Analysis/url_analyzer.py "http://suspicious-example.com/login"
     

---

 5. SIEM Integration (SIEM-Integration/)

 splunk_event_sender.py
    - Description: Sends event data to a Splunk instance via its HTTP Event Collector (HEC).
    - Dependencies: requests
    - Configuration: You'll need to modify the script with your Splunk URL and HEC token.
    - Usage:
     
      python SIEM-Integration/splunk_event_sender.py
      
      (Ensure SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN are set in the script or as environment variables if modified to read them.)

---

 6. Vulnerability Scanning (Vulnerability-Scanning/)

 nmap_scanner.py
    - Description: A wrapper script for Nmap to perform various types of network scans (port scan, version detection, OS detection, default NSE scripts).
    - Dependencies: python-nmap
    - Prerequisite: Nmap must be installed on the system where this script is run.
    - Usage:
      
      python Vulnerability-Scanning/nmap_scanner.py <target_ip_or_hostname> <scan_type>
      
      Scan types: port, version, os, script
    - Example:
     
      python Vulnerability-Scanning/nmap_scanner.py 192.168.1.1 port
      python Vulnerability-Scanning/nmap_scanner.py scanme.nmap.org version
      

---

 7. Web Scraping (Web-Scraping/)

 threat_intel_scraper.py
    - Description: A basic web scraper template designed to extract threat intelligence information (e.g., article titles, IoCs) from a specified webpage. This is a template and likely needs customization for specific websites.
    - Dependencies: requests, beautifulsoup4
    - Configuration: You'll need to adapt the URL and the parsing logic (soup.find_all(...)) within the script to match the structure of the target website.
    - Usage:
    
      python Web-Scraping/threat_intel_scraper.py
      

 📋 Prerequisites

-   Python 3.x
-   pip (Python package installer)
-   Nmap: Required for the Vulnerability-Scanning/nmap_scanner.py script.
    -   Installation: sudo apt-get install nmap (Debian/Ubuntu) or download from [nmap.org](https://nmap.org/download.html).
-   Root/Administrator Privileges: Required for Network-Analysis/network_traffic_analyzer.py to sniff network packets.

 ⚙️ Installation

1.  Clone the repository:
    
    git clone https://github.com/the-cyber-defense/cyber-threat-automation.git
    cd cyber-threat-automation
    

2.  Create a virtual environment (recommended):
    
    python3 -m venv venv
    source venv/bin/activate   On Windows: venv\Scripts\activate
    

3.  Install Python dependencies:
    A requirements.txt file should be created to list all Python package dependencies.
    Based on the scripts, the content of requirements.txt would be:
    txt
    dnspython
    scapy
    requests
    beautifulsoup4
    python-whois
    python-Levenshtein
    python-nmap
    
    You can create this file and then run:
    
    pip install -r requirements.txt
    

 🚀 Usage

Navigate to the directory of the specific tool you want to use and execute the Python script as described in the [Tools Included](-tools-included) section.

General command structure:

python <path_to_script_directory>/<script_name.py> [arguments...]


For example, to run the DNS enumeration script:

python DNS-Recon/dns_enum.py example.com



Remember to:
-   Provide necessary arguments as required by each script.
-   Ensure external dependencies like Nmap are installed if needed.
-   Run scripts requiring packet capture (e.g., network_traffic_analyzer.py) with sudo or as an administrator.

 🤝 Contributing

Contributions are welcome! If you have ideas for improvements, new scripts, or bug fixes, please:

1.  Fork the repository.
2.  Create a new branch (git checkout -b feature/YourFeature or bugfix/YourBugfix).
3.  Make your changes.
4.  Commit your changes (git commit -m 'Add some feature').
5.  Push to the branch (git push origin feature/YourFeature).
6.  Open a Pull Request.

Please ensure your code is well-commented and follows a consistent style.

 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

 ⚠️ Disclaimer

These tools are provided for educational and authorized testing purposes only. Do not use these scripts for any malicious activities or against systems for which you do not have explicit permission. The authors and contributors are not responsible for any misuse or damage caused by these tools. Always act responsibly and ethically.



