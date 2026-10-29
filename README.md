# MikroTik Log Collector & Analyzer

A Python-based CLI tool for automated log extraction and parsing.

## Features
* **Automated Log Fetching:** Establishes a secure SSH connection (`paramiko`) using context managers to safely download system logs.
* **Log Parsing:** Parses raw MikroTik logs into a structured, easy-to-read `.csv` format for further analysis.

## Planned features (code ready, not implemented in CLI yet)
* **Subnet Scanning:** Utilizes `scapy` (ARP requests) to discover active hosts on the local network.
* **Vendor Identification:** Identifies MikroTik devices by matching MAC addresses against the OUIs scraped from netify.ai (fallback list is also present).

## Requirements
* Python 3.13+
* `uv`

## Installation
```bash
git clone https://github.com/kibryt/MikroTik-scanner-log-analyzer.git
cd MikroTik-scanner-log-analyzer
```

## Usage
Run the script from the terminal:
`uv run main.py -h`
This will print required parameters

#### Example usage:
`uv run main.py -i 192.168.88.1 -u admin -p ./logs -f router1_logs1` 
Script returns an error if file already exists.

You will be prompted to securely enter your SSH password.

## Important

Script requires open ssh port on the router and account with proper permissions.
The router’s SSH host key must be known to your machine. Either connect once with a regular ssh client, or pass `--trust-new-host` (unsafe on untrusted networks; the key is not saved, so the flag is needed on every run).

## Architecture
* Designed using **OOP principles** - MikrotikDevice handles the connection, LogAnalyzer parses logs, NetworkScanner finds devices.
* Safe resource management utilizing Python's `@contextmanager` for SSH sessions.
* The password is entered interactively (`getpass`), so it never appears in shell history or process list.
