# Trojan-Hunter

Trojan-Hunter is a Python-based tool for detecting, isolating, and reporting advanced Trojan viruses. This tool supports both **Kali Linux** and **Android (via Termux)**, making it versatile for security enthusiasts and professionals.

---

## Features
- **Real-Time Monitoring**: Detect suspicious files, processes, and network activities.
- **Quarantine Malicious Files**: Automatically isolate infected files.
- **Threat Logging**: Logs all detected threats and actions taken.
- **Cross-Platform**: Works seamlessly on Kali Linux and Termux.

---

## Installation

### On Kali Linux
1. **Update System**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Required Dependencies**:
   ```bash
   sudo apt install python3 python3-pip
   pip3 install psutil scapy yara-python
   ```

3. **Clone the Repository**:
   ```bash
   git clone https://github.com/hackerz-lab/Trojan-Hunter.git
   cd Trojan-Hunter
   ```

4. **Run the Tool**:
   ```bash
   python3 trojan_hunter.py
   ```

### On Android (Termux)
1. **Update Termux**:
   ```bash
   pkg update && pkg upgrade -y
   ```

2. **Install Python and Required Packages**:
   ```bash
   pkg install python
   pip install psutil scapy yara-python
   ```

3. **Clone the Repository**:
   ```bash
   git clone https://github.com/hackerz-lab/Trojan-Hunter.git
   cd Trojan-Hunter
   ```

4. **Run the Tool**:
   ```bash
   python trojan_hunter.py
   ```

---

## How to Use

1. **Run Trojan-Hunter**:
   - Execute the script using `python3 trojan_hunter.py` (Kali Linux) or `python trojan_hunter.py` (Termux).

2. **Monitor Processes**:
   - The tool will scan running processes for suspicious activity and log any detections.

3. **File Scanning**:
   - Add files to the scan directory to check for Trojans. Matches will be logged and quarantined.

4. **Network Monitoring** (Optional):
   - Uncomment the `monitor_network()` function in the script to analyze network traffic (requires root).

---

## Logs and Quarantine
- **Logs**:
  All events are logged in `threat_log.txt` for your review.
- **Quarantine**:
  Infected files are moved to the `quarantine/` directory for safety.

---

## Disclaimer
This tool is for **educational purposes only**. The author is not responsible for any misuse. Use responsibly and only on systems you own or have explicit permission to test.

---

## Contact
- **Author**: Marttin Saji
- **Email**: [Martinsaji26@gmail.com](mailto:Martinsaji26@gmail.com)
- **GitHub**: [hackerz-lab](https://github.com/hackerz-lab)
