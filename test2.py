import os
import socket
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from pysnmp.hlapi import *
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import time

def arp_scan(network):
    print(f"Sending ARP scan to network: {network}")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    start = time.time()
    result = srp(packet, timeout=3, verbose=1)[0]
    end = time.time()

    devices = []
    for sent, received in result:
        rtt = (received.time - sent.sent_time) * 1000  # in ms
        print(f"Received ARP reply from {received.psrc} ({received.hwsrc}) - RTT: {rtt:.2f} ms")
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'arp_rtt_ms': round(rtt, 2)
        })
    return devices


# SNMP sysDescr and hostname lookup
def get_snmp_info(ip, community='ganeshpawar09'):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((ip, 161), timeout=1, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))   # sysName
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication or errorStatus:
            return {'os': 'Unknown', 'hostname': 'Unknown'}

        raw_descr = str(varBinds[0][1])
        hostname = str(varBinds[1][1])

        # Extract just OS name
        if 'windows' in raw_descr.lower():
            os_clean = 'Windows'
        elif 'linux' in raw_descr.lower():
            os_clean = 'Linux'
        elif 'ios' in raw_descr.lower():
            os_clean = 'iOS'
        elif 'mac os' in raw_descr.lower():
            os_clean = 'macOS'
        elif 'android' in raw_descr.lower():
            os_clean = 'Android'
        else:
            os_clean = raw_descr.split()[0]  # fallback: first word

        return {
            'os': os_clean,
            'hostname': hostname
        }
    except Exception:
        return {'os': 'Unknown', 'hostname': 'Unknown'}

# Guess device type from OS string
def guess_device_type(os_string):
    os_string = os_string.lower()
    if 'windows server' in os_string:
        return 'Server'
    elif 'linux' in os_string or 'unix' in os_string:
        return 'Server'
    elif 'windows' in os_string or 'mac os' in os_string or 'ios' in os_string:
        return 'Workstation'
    elif 'android' in os_string:
        return 'Mobile'
    elif 'router' in os_string or 'switch' in os_string:
        return 'Network Device'
    else:
        return 'Unknown'

# MAC vendor lookup
def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return 'Unknown'

# Export to Excel
def export_to_excel(devices, filename='network_inventory1.xlsx'):
    df = pd.DataFrame(devices)
    df.to_excel(filename, index=False)
    print(f"Exported to {filename}")

# Main logic
def main():
    network = "192.168.237.0/24"  
    devices = arp_scan(network)
    print(f"Found {len(devices)} devices")

    with ThreadPoolExecutor(max_workers=20) as executor:
        snmp_results = list(executor.map(lambda d: get_snmp_info(d['ip']), devices))

    for i, device in enumerate(devices):
        device.update(snmp_results[i])
        device['vendor'] = get_mac_vendor(device['mac'])
        device['device_type'] = guess_device_type(device['os'])
        device['status'] = 'Online'  # Responded to ARP, so considered online

    export_to_excel(devices)

if __name__ == "__main__":
    main()
