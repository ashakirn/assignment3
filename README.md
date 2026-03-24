# Network Scanning Automation Tools

**Author:** Ashakirana.V
**Assignment:** Module 3 - Cybersecurity and Ethical Hacking

---

## Overview

This repository contains three Python-based network reconnaissance tools developed as part of a cybersecurity internship assignment.

| Script | Technique | Library |
|--------|-----------|---------|
| ping_scanner.py | ICMP Ping - host reachability and RTT | subprocess, platform, re |
| arp_scanner.py | ARP cache - IP to MAC address mapping | subprocess, platform, re |
| nmap_scanner.py | Port, service, OS scanning via Nmap | python-nmap, subprocess |

---

## Requirements

Install Nmap:

    sudo apt-get install nmap

Install Python library:

    pip install python-nmap

---

## Task 1 - Ping Scanner

Sends ICMP ping requests to one or more hosts and reports reachability and average response time.

Features:
- Single or multiple host scanning
- Cross-platform: Windows, Linux, macOS
- Extracts average RTT
- Handles timeouts and errors

How to run:

    python3 Task1/ping_scanner.py

---

## Task 2 - ARP Scanner

Reads the system ARP cache and displays IP to MAC address mappings.

Features:
- Reads system ARP table
- Cross-platform: Windows, Linux, macOS
- Shows IP, MAC address, and interface
- Optional save to file

How to run:

    python3 Task2/arp_scanner.py

---

## Task 3 - Nmap Scanner

Interactive menu-driven Nmap scanner with five scan types.

Scan Types:
1. Host Discovery (-sn)
2. Port Scan ports 1-1000 (-sT)
3. Custom Port Scan
4. Service Detection (-sV)
5. OS Detection (-O) - requires sudo

How to run:

    python3 Task3/nmap_scanner.py

For OS Detection:

    sudo python3 Task3/nmap_scanner.py

---

## Repository Structure

    assignment3/
    ├── Task1/
    │   ├── ping_scanner.py
    │   └── screenshots/
    ├── Task2/
    │   ├── arp_scanner.py
    │   └── screenshots/
    ├── Task3/
    │   ├── nmap_scanner.py
    │   └── screenshots/
    └── README.md

---

## Testing

Test on localhost first:

    python3 Task1/ping_scanner.py
    python3 Task2/arp_scanner.py
    python3 Task3/nmap_scanner.py

---

## Security and Ethics

Only scan networks you own or have explicit permission to scan.
Unauthorized scanning is illegal.
For educational purposes only.

---

## References

- Python subprocess: https://docs.python.org/3/library/subprocess.html
- Python platform: https://docs.python.org/3/library/platform.html
- Nmap: https://nmap.org
- python-nmap: https://pypi.org/project/python-nmap/


