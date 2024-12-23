# ---------------------------------------------
# TROJAN-HUNTER
# ---------------------------------------------
# Author: Marttin Saji
# Email: Martinsaji26@gmail.com
# GitHub: hackerz-lab
# ---------------------------------------------

import os
import psutil
import yara
import scapy.all as scapy
from shutil import move
from datetime import datetime

# ASCII Art for Trojan-Hunter
print(r"""
 
╔════╗───────────╔╗─╔╗─────╔╗
║╔╗╔╗║───╔╗──────║║─║║────╔╝╚╗
╚╝║║╠╩╦══╬╬══╦═╗─║╚═╝╠╗╔╦═╬╗╔╬══╦═╗
──║║║╔╣╔╗╠╣╔╗║╔╗╗║╔═╗║║║║╔╗╣║║║═╣╔╝
──║║║║║╚╝║║╔╗║║║║║║─║║╚╝║║║║╚╣║═╣║
──╚╝╚╝╚══╣╠╝╚╩╝╚╝╚╝─╚╩══╩╝╚╩═╩══╩╝
────────╔╝║
────────╚═╝
 
        TROJAN-HUNTER - Your Virus Defense System
""")

# Define YARA rules for Trojan detection
YARA_RULES = """
rule TrojanExample {
    strings:
        $malicious_string = "malicious_code"
    condition:
        $malicious_string
}
"""

def log_event(event):
    """Log events to a file."""
    with open("threat_log.txt", "a") as log:
        log.write(f"{datetime.now()} - {event}\n")

def scan_file(file_path):
    """Scan files for Trojans using YARA."""
    rules = yara.compile(source=YARA_RULES)
    try:
        matches = rules.match(file_path)
        if matches:
            log_event(f"Malicious file detected: {file_path}")
            quarantine(file_path)
    except Exception as e:
        log_event(f"Error scanning {file_path}: {e}")

def quarantine(file_path):
    """Move the malicious file to a quarantine folder."""
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    move(file_path, quarantine_dir)
    log_event(f"Quarantined: {file_path}")

def monitor_processes():
    """Monitor processes for suspicious activity."""
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            process_name = process.info['name']
            if "suspicious" in process_name.lower():  # Example condition
                log_event(f"Suspicious process detected: {process_name}")
                process.terminate()
        except psutil.AccessDenied:
            continue

def monitor_network():
    """Monitor network traffic for anomalies."""
    def analyze_packet(packet):
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            log_event(f"Packet: {src} -> {dst}")
            # Add conditions to detect anomalies here

    scapy.sniff(prn=analyze_packet, store=False)

def main():
    print("Starting Trojan-Hunter...")
    log_event("Tool started.")
    # Call monitoring functions here
    monitor_processes()
    # Uncomment for network monitoring (requires root)
    # monitor_network()

if __name__ == "__main__":
    main()
