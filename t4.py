from pysnmp.hlapi import *

def snmp_get(oid, host, community='public', port=161):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community, mpModel=0),
               UdpTransportTarget((host, port)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )
    if errorIndication:
        print(f"SNMP Error: {errorIndication}")
        return None
    elif errorStatus:
        print(f"SNMP Error: {errorStatus.prettyPrint()} at {errorIndex}")
        return None
    else:
        for varBind in varBinds:
            return str(varBind[1])
    return None

def check_firmware_version(host, community='public', approved_versions=None):
    oid_sysdescr = '1.3.6.1.2.1.1.1.0'
    sys_descr = snmp_get(oid_sysdescr, host, community)
    
    if sys_descr:
        print(f"\nSystem Description: {sys_descr}")
        if approved_versions:
            for version in approved_versions:
                if version in sys_descr:
                    print("Firmware Compliance: ✅ Compliant")
                    return
            print("Firmware Compliance: ❌ Non-compliant")
        else:
            print("Approved version list not provided")
    else:
        print("Could not retrieve system description")

if __name__ == "__main__":
    device_ip = "192.168.237.68"  # Your device IP
    community_string = "public"
    
    # Add approved versions (substring match)
    approved_firmware_versions = [
        "Windows Version 6.3",
        "IOS-XE 17.9",
        "Firmware v5.2.1"
    ]
    
    check_firmware_version(device_ip, community_string, approved_firmware_versions)
