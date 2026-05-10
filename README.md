# MikroTik Network Automation & Analyzer

A Python-based CLI tool for network scanning, MikroTik device identification, automated log extraction, and parsing.

## Features
* **Subnet Scanning:** Utilizes `scapy` (ARP requests) to discover active hosts on the local network.
* **Vendor Identification:** Identifies MikroTik devices by matching MAC addresses against the Netify OUI API.
* **Automated Log Fetching:** Establishes a secure SSH connection (`paramiko`) using context managers to safely download system logs.
* **Log Parsing:** Parses raw MikroTik logs into a structured, easy-to-read `.csv` format for further analysis.

## Requirements
* Python 3.8+
* `uv sync`

## Usage
Run the script from the terminal providing the target IP and SSH username:
`uv run main.py -i <MIKROTIK_IP> -u <USERNAME>`

You will be prompted to securely enter your SSH password.

## Architecture
* Designed using **OOP principles** (Encapsulation, Single Responsibility).
* Safe resource management utilizing Python's `@contextmanager` for SSH sessions.
* Avoids hardcoded credentials by using `argparse` and `getpass`.