# Packet Sniffer Tool

## Overview

This is a Python-based packet sniffer that captures and analyzes network packets. The tool displays relevant information such as:
- Source and destination IP addresses
- Protocols (TCP, UDP, ICMP)
- Packet payload data (if available)

**Author:** Thaslim Mohamed

## Features

- Captures and analyzes packets in real-time.
- Displays source and destination IP addresses.
- Identifies common protocols (TCP, UDP, ICMP).
- Extracts and displays packet payload data (when available).

## Requirements

- Python 3.x
- `scapy` library

## Installation

1. Clone the repository or download the script.
2. Install the required library:
   ```bash
   pip install scapy
Usage
Run the script as an administrator or with sudo:
bash
Copy code
sudo python packet_sniffer.py
The tool will start capturing packets in real-time. Press Ctrl+C to stop the program.
Example Output
When a packet is captured, the output might look like this:

yaml
Copy code
Packet Captured:
Source IP: 192.168.1.2
Destination IP: 8.8.8.8
Protocol: 6
Protocol Type: TCP
Payload: GET / HTTP/1.1
Notes
Permissions: Capturing packets typically requires administrative privileges. Run the program with sudo or as an administrator.
Ethical Use: Use this tool responsibly and only on networks you own or have permission to monitor.
Payload Data: The tool displays payload data when available. Sensitive data should be handled with care.
Disclaimer
This tool is for educational purposes only. Unauthorized use of this tool to monitor network traffic may violate privacy laws. Use it only on authorized networks or systems.

Author
Name: Thaslim Mohamed
Contact: [Your Contact Information Here]
License
This project is licensed under the MIT License.

Troubleshooting
Permission Error: Ensure you run the program as an administrator or with sudo.
Dependencies: Make sure you have the scapy library installed.
Contributions
Contributions to enhance this tool are welcome. Submit pull requests or open issues for suggestions.

yaml
Copy code

---

### **Ethical Disclaimer**
This tool is intended for learning and educational purposes only. Unauthorized packet sniffing is illegal and unethical. Always obtain proper authorization before using this tool on any network. 

Let me know if you need additional features or enhancements, such as saving captured packets to a file or filtering by specific protocols!
