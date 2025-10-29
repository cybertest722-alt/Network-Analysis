# Network Analysis Practical Project

## Overview
This project demonstrates hands-on **network traffic analysis** using both **Wireshark** and **TCPDump**. The exercises focus on capturing, filtering, and investigating real-world network packets, as well as performing deep inspection of a **malicious PCAP file**.  

The goal of this practical is to showcase professional skills in **Blue Team network monitoring**, **packet-level analysis**, and **malware traffic investigation** all essential for a **SOC Analyst** or **Cybersecurity Professional**.

---

## 🎯 Objectives
- Capture and analyze live network traffic using **Wireshark** and **TCPDump**
- Examine packets to identify network protocols, sessions, and anomalies
- Investigate **malicious PCAPs** and uncover indicators of compromise (IOCs)
- Demonstrate command-line expertise using **TCPDump** for forensic analysis

---

## Tools & Technologies
| Tool | Purpose |
|------|----------|
| **Wireshark** | GUI-based packet capture and protocol analysis |
| **TCPDump** | Command-line packet capture and filtering |
| **PCAP Files** | Used for replaying and analyzing recorded network traffic |
| **Protocols Covered** | TCP, UDP, HTTP, DNS, ICMP, ARP, and others |

---

##  Activities

### 1️⃣ Wireshark Activity – Traffic Analysis
Analysed two PCAP files to:
- Identify source and destination hosts  
- Filter packets using display filters (`ip.src`, `tcp.port`, `http.request`, etc.)  
- Trace TCP streams and reconstruct HTTP sessions  
- Detect abnormal or suspicious traffic patterns  

**Skills demonstrated:** Protocol dissection, filtering, conversation tracking, and traffic visualization.

---

### 2️⃣ TCPDump Activity – Command-Line Network Analysis
Used **TCPDump** to capture and analyze packets directly from the terminal:
- Applied capture filters (`tcp`, `udp`, `port 80`, `host 192.168.1.10`)  
- Extracted metadata and protocol statistics from PCAPs  
- Verified specific communications between endpoints  
- Practiced command-line traffic analysis for real-world SOC workflows  

---

**Example Commands:**
- tcpdump -i eth0 -w capture.pcap
- tcpdump -r capture.pcap tcp and port 443
- tcpdump -nnvvXSs 0 -r capture.pcap | grep "SYN"

---

### 3️⃣ Malicious PCAP Investigation – Course Challenge

Investigated a malicious PCAP to uncover evidence of compromise:

- Identified compromised hosts and potential attacker IPs  
- Detected C2 (Command & Control) traffic and beaconing activity  
- Found suspicious domains, payloads, and data exfiltration attempts  
- Traced malware behavior through HTTP and DNS tunnels  

**Analysis Techniques:**
- Following TCP/HTTP streams to decode payloads  
- Extracting malicious binaries and scripts from captured packets  
- Mapping indicators of compromise (IOCs) to MITRE ATT&CK tactics  

**Outcome:** Generated a detailed investigation report with findings, IOCs, and mitigation recommendations.

---

### Key Learnings

- Proficiency with Wireshark filters and TCPDump syntax  
- Improved understanding of network protocol structures  
- Ability to detect malicious network behaviors and anomalies  
- Strengthened SOC analysis and incident response capabilities  

---

### Example Filters & Commands

**Wireshark Display Filters:**

- ip.addr == 192.168.1.10
- http.request
- tcp.flags.syn == 1
- dns.qry.name contains "malicious"

---

### Conclusion

This project showcases end-to-end expertise in Network Traffic Analysis, from packet capture to malware traffic investigation.
It demonstrates practical Blue Team skills in identifying, filtering, and interpreting network activity essential for roles in SOC operations, threat hunting, and cyber defense.

Through this project, I gained a deeper understanding of how attackers operate at the network level and how defenders can trace, detect, and respond effectively using open-source tools.

---

### Author

**Ilo Paul Okechukwu**  
Cybersecurity & Network Analysis Enthusiast  
Blue Team | SOC Analysis | Network Forensics  
[LinkedIn](https://www.linkedin.com/in/paulokechukwuilo)



---
