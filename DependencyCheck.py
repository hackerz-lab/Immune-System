import os
import subprocess
import sys

required_packages = ["psutil", "scapy", "yara-python"]

def install_packages():
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing missing package: {package}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install_packages()
