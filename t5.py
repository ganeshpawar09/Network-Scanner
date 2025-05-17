from pysnmp.hlapi import *

def snmp_get(host, community, oid, port=161):
    error_indication, error_status, error_index, var_binds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((host, port)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )

    if error_indication:
        print(f"Error: {error_indication}")
        return None
    elif error_status:
        print(f"Error: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index)-1][0] or '?'}")
        return None
    else:
        for var_bind in var_binds:
            return str(var_bind[1])

def get_device_inventory(host, community='public'):
    print(f"Getting inventory for device {host}")
    
    # Common SNMP OIDs for inventory info
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
        'sysServices': '1.3.6.1.2.1.1.7.0',
    }

    inventory = {}
    for key, oid in oids.items():
        value = snmp_get(host, community, oid)
        inventory[key] = value if value else 'N/A'

    print(f"Device: {inventory['sysName']}")
    print(f"Description: {inventory['sysDescr']}")
    print(f"Object ID: {inventory['sysObjectID']}")
    print(f"Uptime (ticks): {inventory['sysUpTime']}")
    print(f"Contact: {inventory['sysContact']}")
    print(f"Location: {inventory['sysLocation']}")
    print(f"Services: {inventory['sysServices']}")
    print("-" * 40)
    return inventory

if __name__ == "__main__":
    devices = [
        {'host': '192.168.237.68', 'community': 'public'},
    ]
    for device in devices:
        get_device_inventory(device['host'], device['community'])
