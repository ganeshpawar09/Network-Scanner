from pysnmp.hlapi import *

def check_snmp(host='192.168.237.190', community='ganeshpawar09', port=161, oid='1.3.6.1.2.1.1.1.0'):
    """
    Check if SNMP is active by querying the system description OID.
    """
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMPv2c
        UdpTransportTarget((host, port), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        return f"SNMP not responding: {errorIndication}"
    elif errorStatus:
        return f"SNMP error: {errorStatus.prettyPrint()}"
    else:
        for varBind in varBinds:
            return f"SNMP is active. Response: {varBind}"

# Example usage
print(check_snmp())
