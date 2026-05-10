import requests
import re
from scapy.layers.l2 import ARP, Ether, srp
from contextlib import contextmanager
import paramiko
import csv
from pathlib import Path
import argparse
import getpass

def main():
    parser = argparse.ArgumentParser(description="MikroTik Network Scanner & Log Analyzer")
    parser.add_argument("-i", "--ip", required=True, help="MikroTik IP Address")
    parser.add_argument("-u", "--user", required=True, help="SSH username")
    parser.add_argument("-p", "--path", default=".", help="Save path (default is current folder)")
    parser.add_argument("-f", "--filename", default="mikrotik_logs", help="File name")

    args = parser.parse_args()

    password = getpass.getpass(prompt=f'Enter the password for {args.user}@{args.ip}: ')
    print("Connecting...")
    mikrotik = MikrotikDevice(args.ip)
    full_log_path = Path(args.path) / f"{args.filename}.txt"
    mikrotik.get_logs(args.user, password, args.filename, str(full_log_path))
    if full_log_path.exists():
        print("Analysing...")
        analyze = LogAnalyzer(full_log_path)
        analyze.parse_logs(str(Path(args.path) / args.filename))
        print("Results saved to csv file.")
    else:
        print("Couldn't collect any logs.")


class NetworkScanner:
    def __init__(self, address, mask):
        self.address = address
        self.mask = mask
        self.timeout = 1
        self.active_hosts = []
        self.mikrotik_devices = []

    @staticmethod
    def getmacs():
        try:
            response = requests.get("https://www.netify.ai/resources/macs/brands/mikrotik")
            return [mac.upper() for mac in re.findall(r"(?:[0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}", response.text)]
        except:
            return ['00:0C:42', '08:55:31', '18:FD:74', '2C:C8:1B', '48:8F:5A', '48:A9:8A', '4C:5E:0C', '64:D1:54', '6C:3B:6B', '74:4D:28', '78:9A:18', 'C4:AD:34', 'CC:2D:E0', 'D4:01:C3', 'D4:CA:6D', 'DC:2C:6E', 'E4:8D:8C', 'F4:1E:57', 'B8:69:F4', '04:F4:1C', 'D0:EA:11']

    def scan(self):
        try:
            arp = ARP(pdst=f'{self.address}/{self.mask}')
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            packet = ether/arp
            result = srp(packet, timeout=2, verbose=0)[0]
            for sent, received in result:
                host_ip = received.psrc
                host_mac = received.hwsrc
                self.active_hosts.append({host_ip : host_mac})
        except Exception as e:
            print(f'Error while scanning: {e}')

    def find_mikrotik_devices(self):
        macs = self.getmacs()
        for device in self.active_hosts:
            for ip, mac in device.items():
                if mac[0:8].upper() in macs:
                    self.mikrotik_devices.append(ip)


class MikrotikDevice:
    def __init__(self, ip):
        self.ip = ip

    @contextmanager
    def set_connection(self, login, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.ip, port=22, username=login, password=password)
        except Exception as e:
            print(f'Error during connecting: {e}')
            yield None
        else:
            yield client
        finally:
            client.close()
            print('Connection closed')

    def get_logs(self, login, password, filename, localpath):
        localpath = Path(localpath)
        with self.set_connection(login, password) as ssh_connection:
            if ssh_connection is None:
                return None
            stdin, stdout, stderr = ssh_connection.exec_command(f'/log print file={filename}')
            status = stdout.channel.recv_exit_status()
            if status == 0:
                try:
                    sftp_client = ssh_connection.open_sftp()
                    sftp_client.get(f'{filename}.txt', localpath)
                    sftp_client.close()
                except Exception as e:
                    print(f'Error occurred during file transfer: {e}')
            return None

    def get_conf_backup(self, login, password, filename, localpath):
        with self.set_connection(login, password) as ssh_connection:
            if ssh_connection is None:
                return None
            stdin, stdout, stderr = ssh_connection.exec_command(f'/system backup save name={filename}')
            status = stdout.channel.recv_exit_status()
            if status == 0:
                try:
                    sftp_client = ssh_connection.open_sftp()
                    sftp_client.get(f'{filename}.backup', localpath)
                    sftp_client.close()
                except Exception as e:
                    print(f'Error occurred during file transfer: {e}')
            return None


class LogAnalyzer:
    def __init__(self, file):
        self.file = Path(file)

    def parse_logs(self, output_file):
        output_file = Path(f'{output_file}.csv')
        if output_file.is_file():
            raise FileExistsError('File already exists. Using this program you have to provide a new filename.')
        with open(self.file, 'r', newline='', encoding='utf-8') as file_in, open(output_file, 'w', newline='', encoding='utf-8') as output:
            fields = ['timestamp', 'device', 'level', 'description', 'message']
            csvwriter = csv.writer(output)
            csvwriter.writerow(fields)
            for line in file_in:
                if '#' in line:
                    continue
                parted_log = line.strip().split(' ', maxsplit=3)
                if len(parted_log) < 4:
                    continue
                separated = parted_log[2].split(',')
                device = separated[0]
                if len(separated) == 3:
                    level = separated[1]
                    description = separated[2]
                else:
                    level = 'N/A'
                    description = separated[1]
                timestamp = f'{parted_log[0]} {parted_log[1]}'
                message = parted_log[3]
                row = [timestamp, device, level, description, message]
                csvwriter.writerow(row)


if __name__ == "__main__":
    main()