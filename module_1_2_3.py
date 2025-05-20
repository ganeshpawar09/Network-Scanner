import socket
import nmap
from icmplib import ping
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor
from mac_vendor_lookup import MacLookup
import pandas as pd
import os

os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"

def arp_scan(network):
    print(f"Sending ARP scan to network: {network}")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=1)[0]  # Use verbose=1 for debugging

    devices = []
    for sent, received in result:
        print(f"Received ARP reply from {received.psrc} ({received.hwsrc})")
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def nmap_os_detection(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O -Pn')

        if ip in nm.all_hosts() and 'osmatch' in nm[ip]:
            osmatches = nm[ip]['osmatch']
            if osmatches:
                return osmatches[0]['name']
        return 'Unknown'

    except Exception as e:
        print(f"nmap scan failed for {ip}: {e}")
        print(nm[ip] if ip in nm.all_hosts() else "No scan data available.")
        return 'Unknown'

def guess_device_type(os_name):
    os_name = os_name.lower()
    if 'windows server' in os_name:
        return 'Server'
    elif 'linux' in os_name or 'unix' in os_name:
        return 'Server' 
    elif 'ios' in os_name or 'mac os' in os_name or 'windows' in os_name:
        return 'Workstation'
    elif 'android' in os_name:
        return 'Mobile'
    else:
        return 'Unknown'

def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return 'Unknown'

def tcp_ping(ip, ports=[445, 135, 139, 80, 22], timeout=1):
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except:
            continue
    return False

def check_reachability(ip):
    try:
        result = ping(ip, count=3, timeout=1)
        if result.is_alive:
            return {
                'is_alive': True,
                'avg_rtt_ms': result.avg_rtt,
                'packet_loss_percent': 100 - (result.packets_received / result.packets_sent * 100)
            }
        # ICMP blocked? Try TCP ping fallback
        if tcp_ping(ip):
            return {
                'is_alive': True,
                'avg_rtt_ms': None,
                'packet_loss_percent': 0
            }
        return {
            'is_alive': False,
            'avg_rtt_ms': None,
            'packet_loss_percent': 100
        }
    except Exception:
        return {
            'is_alive': False,
            'avg_rtt_ms': None,
            'packet_loss_percent': 100
        }
def export_to_excel(devices, filename='network_inventory.xlsx'):
    df = pd.DataFrame(devices)
    df.to_excel(filename, index=False)
    print(f"Device data exported to {filename}")

def main():
    network = "192.168.237.0/24"
    print("Running ARP scan...")
    devices = arp_scan(network)

    print(f"Found {len(devices)} devices. Gathering hostnames, OS info, and vendors...")

    with ThreadPoolExecutor(max_workers=20) as executor:
        hostnames = list(executor.map(lambda d: get_hostname(d['ip']), devices))
        os_list = list(executor.map(lambda d: nmap_os_detection(d['ip']), devices))
        reachability = list(executor.map(lambda d: check_reachability(d['ip']), devices))

    for i, device in enumerate(devices):
        device['hostname'] = hostnames[i] if hostnames[i] else 'Unknown'
        device['os'] = os_list[i]
        device['vendor'] = get_mac_vendor(device['mac'])
        device['device_type'] = guess_device_type(device['os'])
        device.update(reachability[i])

    print("\n--- Network Device Inventory ---")

    export_to_excel(devices)

    # for device in devices:
    #     print(f"IP: {device['ip']}")
    #     print(f"MAC: {device['mac']}")
    #     print(f"Vendor: {device['vendor']}")
    #     print(f"Hostname: {device['hostname']}")
    #     print(f"OS: {device['os']}")
    #     print(f"Device Type: {device['device_type']}")
    #     print(f"Status: {'Online' if device['is_alive'] else 'Offline'}")
    #     print(f"Avg RTT: {device['avg_rtt_ms']} ms")
    #     print(f"Packet Loss: {device['packet_loss_percent']}%\n")

if __name__ == "__main__":
    main()
