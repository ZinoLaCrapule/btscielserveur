import subprocess
from db import save_device

def scan_network(interface='eth0'):
    result = subprocess.run(['sudo', 'arp-scan', '--interface', interface, '--localnet'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    for line in lines:
        parts = line.split('\t')
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip()
            save_device(ip, mac)
