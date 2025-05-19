import socket

def is_udp_port_open(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (ip, port))  # Send empty UDP packet

        # Wait to see if an error or response is received (rare for UDP)
        try:
            data, _ = sock.recvfrom(1024)
            return True  # Got some response
        except socket.timeout:
            # No response doesn't mean closed for UDP
            return True  # Assume open if no ICMP "port unreachable"
        finally:
            sock.close()

    except Exception:
        return False


ip = '192.168.237.190'
print("Port 161 (SNMP):", "Open" if is_udp_port_open(ip, 161) else "Closed")
print("Port 162 (SNMP Trap):", "Open" if is_udp_port_open(ip, 162) else "Closed")
