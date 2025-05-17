from pysnmp.hlapi import *

def snmp_walk(ip, community, oid):
    # Generator to perform SNMP walk on given OID
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),  # SNMP v2c
                              UdpTransportTarget((ip, 161)),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid)),
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex)-1][0] or "?"}')
            break
        else:
            for varBind in varBinds:
                yield varBind

def get_interface_stats(ip, community):
    # OIDs
    OID_ifDescr = '1.3.6.1.2.1.2.2.1.2'
    OID_ifInOctets = '1.3.6.1.2.1.2.2.1.10'
    OID_ifOutOctets = '1.3.6.1.2.1.2.2.1.16'
    OID_ifInErrors = '1.3.6.1.2.1.2.2.1.14'
    OID_ifOutErrors = '1.3.6.1.2.1.2.2.1.20'
    OID_ifInDiscards = '1.3.6.1.2.1.2.2.1.13'
    OID_ifOutDiscards = '1.3.6.1.2.1.2.2.1.19'
    OID_ifOperStatus = '1.3.6.1.2.1.2.2.1.8'

    interfaces = {}

    # Walk interface descriptions first to get interface indexes
    for varBind in snmp_walk(ip, community, OID_ifDescr):
        oid, descr = varBind
        # Extract interface index from OID suffix
        ifIndex = int(oid.prettyPrint().split('.')[-1])
        interfaces[ifIndex] = {'description': str(descr)}

    # For each metric, fetch values and store by interface index
    for ifIndex in interfaces.keys():
        for oid_base, key in [(OID_ifInOctets, 'in_octets'),
                              (OID_ifOutOctets, 'out_octets'),
                              (OID_ifInErrors, 'in_errors'),
                              (OID_ifOutErrors, 'out_errors'),
                              (OID_ifInDiscards, 'in_discards'),
                              (OID_ifOutDiscards, 'out_discards'),
                              (OID_ifOperStatus, 'oper_status')]:

            oid = f"{oid_base}.{ifIndex}"
            iterator = getCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, 161)),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid)))

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex)-1][0] or "?"}')
            else:
                for varBind in varBinds:
                    interfaces[ifIndex][key] = varBind[1]

    return interfaces

def print_interface_stats(interfaces):
    print("\n--- Interface Stats ---")
    for ifIndex, stats in interfaces.items():
        print(f"Interface {ifIndex}: {stats['description']}")
        print(f"  Operational Status: {'Up' if stats['oper_status'] == 1 else 'Down'}")
        print(f"  In Octets: {stats.get('in_octets', 'N/A')}")
        print(f"  Out Octets: {stats.get('out_octets', 'N/A')}")
        print(f"  In Errors: {stats.get('in_errors', 'N/A')}")
        print(f"  Out Errors: {stats.get('out_errors', 'N/A')}")
        print(f"  In Discards: {stats.get('in_discards', 'N/A')}")
        print(f"  Out Discards: {stats.get('out_discards', 'N/A')}")
        print()

if __name__ == "__main__":
    device_ip = "192.168.237.68"
    community = "public"

    interfaces = get_interface_stats(device_ip, community)
    print_interface_stats(interfaces)
