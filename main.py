#!/usr/bin/env python3

import requests
import re
from contextlib import contextmanager
import paramiko
import csv
from pathlib import Path
import argparse
import getpass
import sys
import time

# Constants and safety fucntion

OUI_URL = "https://www.netify.ai/resources/macs/brands/mikrotik"
FALLBACK_MIKROTIK = {
    '00:0C:42', '08:55:31', '18:FD:74', '2C:C8:1B', '48:8F:5A', '48:A9:8A',
    '4C:5E:0C', '64:D1:54', '6C:3B:6B', '74:4D:28', '78:9A:18', 'C4:AD:34',
    'CC:2D:E0', 'D4:01:C3', 'D4:CA:6D', 'DC:2C:6E', 'E4:8D:8C', 'F4:1E:57',
    'B8:69:F4', '04:F4:1C', 'D0:EA:11',
}
LOG_LEVELS = {"debug", "info", "warning", "error", "critical"}
SAFE_FILENAME = re.compile(r"[A-Za-z0-9_.-]+") # used to prevent command injection
LOG_LINE = re.compile(
    r"^(?P<timestamp>.+?)\s+"
    r"(?P<topics>[a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*)\s+"
    r"(?P<message>.+)$"
)
CSV_FIELDS = ["timestamp", "topics", "level", "message"]

def safe_filename(value):
    if not SAFE_FILENAME.fullmatch(value):
        raise argparse.ArgumentTypeError("use only letters, digits, '_', '-' and '.' in the file name")
    return value

# Entry point

def parse_args():
    parser = argparse.ArgumentParser(description="MikroTik Log Collector")
    parser.add_argument("-i", "--ip", required=True, help="MikroTik IP address")
    parser.add_argument("-u", "--user", required=True, help="SSH username")
    parser.add_argument("-p", "--path", default=".", help="Folder to save files in (default: current folder)")
    parser.add_argument("-f", "--filename", default="mikrotik_logs", type=safe_filename, help="File name without extension (default: mikrotik_logs)")
    parser.add_argument("--trust-new-host", action="store_true", help="Accept the router's SSH host key if it is not known yet")
    # parser.add_argument("-s", "--scan", metavar="NETWORK", help="Scan a network for MikroTik devices, e.g. 192.168.88.0/24 (needs root)")

    args = parser.parse_args()
    # if not args.scan and not (args.ip and args.user):
    #     parser.error("-i and -u are required unless --scan is used")
    return args


def main():
    args = parse_args()

    out_dir = Path(args.path)
    out_dir.mkdir(parents=True, exist_ok=True)
    txt_path = out_dir / f"{args.filename}.txt"
    csv_path = out_dir / f"{args.filename}.csv"

    if csv_path.exists():
        sys.exit(f"{csv_path} already exists. Provide a new --filename.")

    password = getpass.getpass(prompt=f'Enter the password for {args.user}@{args.ip}: ')
    print("Connecting...")
    mikrotik = MikrotikDevice(args.ip, trust_new_host=args.trust_new_host)

    if not mikrotik.get_logs(args.user, password, args.filename, txt_path):
        sys.exit("Couldn't collect any logs.")

    print("Analysing...")
    rows = LogAnalyzer(txt_path).parse_logs(csv_path)
    print(f"Saved {rows} log entries to {csv_path}")


class NetworkScanner:
    def __init__(self, address, mask):
        self.address = address
        self.mask = mask
        self.timeout = 1
        self.active_hosts = {}
        self.mikrotik_devices = []

    @staticmethod
    def getmacs():
        try:
            response = requests.get(OUI_URL, timeout=10)
            response.raise_for_status()
        except requests.RequestException:
            return FALLBACK_MIKROTIK

        found = {mac.upper() for mac in re.findall(r"(?:[0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}", response.text)}
        return found or FALLBACK_MIKROTIK

    def scan(self):
        from scapy.layers.l2 import ARP, Ether, srp
        try:
            arp = ARP(pdst=f'{self.address}/{self.mask}')
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            packet = ether/arp
            answered, _ = srp(packet, timeout=self.timeout, verbose=0)
            for _, received in answered:
                self.active_hosts[received.psrc] = received.hwsrc
        except Exception as e:
            print(f'Error while scanning: {e}')

        # return self.active_hosts # might be useful in future

    def find_mikrotik_devices(self):
        macs = self.getmacs()
        self.mikrotik_devices = [ip for ip, mac in self.active_hosts.items() if mac[:8].upper() in macs]


class MikrotikDevice:
    def __init__(self, ip, port=22, timeout=10, trust_new_host=False):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.trust_new_host = trust_new_host

    @contextmanager
    def set_connection(self, login, password):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if self.trust_new_host else paramiko.RejectPolicy())
        connected = False
        try:
            client.connect(hostname=self.ip, port=self.port, username=login, password=password, timeout=self.timeout, look_for_keys=False, allow_agent=False)
            connected = True
        except paramiko.AuthenticationException:
            print("Authentication failed: wrong username or password.")
        except (paramiko.SSHException, OSError) as e:
            print(f"Couldn't connect: {e}")

        try:
            yield client if connected else None
        finally:
            client.close()
            if connected:
                print("Connection closed")

    def _export_and_download(self, login, password, command, remote_name, local_path):
        with self.set_connection(login, password) as ssh:
            if ssh is None:
                return False

            _, stdout, stderr = ssh.exec_command(command)

            if stdout.channel.recv_exit_status() != 0:
                print(f"Router returned an error: {stderr.read().decode().strip()}")
                return False

            try:
                # time.sleep(1) # solution to possible error caused by too quick transfer attempt
                with ssh.open_sftp() as sftp:
                    sftp.get(remote_name, str(local_path))
                    try:
                        sftp.remove(remote_name)
                    except OSError as e:
                        print(f"Couldn't remove {remote_name} from the router: {e}")
            except (OSError, paramiko.SSHException) as e:
                print(f"Error occurred during file transfer: {e}")
                return False
            return True

    def get_logs(self, login, password, filename, localpath):
        safe_filename(filename)
        return self._export_and_download(login, password, command=f"/log print file={filename}", remote_name=f"{filename}.txt", local_path=localpath)

    def get_conf_backup(self, login, password, filename, localpath):
        safe_filename(filename)

        return self._export_and_download(login, password, command=f"/system backup save name={filename}", remote_name=f"{filename}.backup", local_path=localpath)


class LogAnalyzer:
    def __init__(self, file):
        self.file = Path(file)

    @staticmethod
    def _parse_line(line):
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        match = LOG_LINE.match(line)
        if match is None:
            return None

        topics = match["topics"].split(",")
        level = next((t for t in topics if t in LOG_LEVELS), "N/A")
        other_topics = [t for t in topics if t != level]
        return [match["timestamp"], ",".join(other_topics), level, match["message"]]

    def parse_logs(self, output_file):
        rows = 0
        with open(self.file, "r", encoding="utf-8") as src, open(output_file, "x", newline="", encoding="utf-8") as dst:
            writer = csv.writer(dst)
            writer.writerow(CSV_FIELDS)
            for line in src:
                row = self._parse_line(line)
                if row is None:
                    continue
                writer.writerow(row)
                rows += 1
        return rows


if __name__ == "__main__":
    main()