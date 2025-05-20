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
        print(f"Error: {errorIndication}")
        return None
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()} at {errorIndex}")
        return None
    else:
        for varBind in varBinds:
            return varBind[1]
    return None

def snmp_walk(oid, host, community='public', port=161):
    result = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((host, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False):

        if errorIndication:
            print(f"Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"Error: {errorStatus.prettyPrint()} at {errorIndex}")
            break
        else:
            for varBind in varBinds:
                result.append(varBind)
    return result

def get_cpu_load(host, community='public'):
    # Walk CPU load per core
    cpu_loads = snmp_walk('1.3.6.1.2.1.25.3.3.1.2', host, community)
    if not cpu_loads:
        print("Could not get CPU load")
        return None
    # Average CPU load across cores
    loads = [int(x[1]) for x in cpu_loads]
    avg_load = sum(loads) / len(loads)
    return avg_load

def get_memory_usage(host, community='public'):
    # Get total RAM in KB
    total_mem = snmp_get('1.3.6.1.2.1.25.2.2.0', host, community)
    if total_mem is None:
        print("Could not get total memory")
        return None

    # Walk hrStorageTable to find RAM used (hrStorageType == 1.3.6.1.2.1.25.2.1.2)
    hrStorageType_oid = '1.3.6.1.2.1.25.2.3.1.2'
    hrStorageUsed_oid = '1.3.6.1.2.1.25.2.3.1.6'
    hrStorageSize_oid = '1.3.6.1.2.1.25.2.3.1.5'

    types = snmp_walk(hrStorageType_oid, host, community)
    used = snmp_walk(hrStorageUsed_oid, host, community)
    size = snmp_walk(hrStorageSize_oid, host, community)

    for i in range(len(types)):
        if str(types[i][1]) == '1.3.6.1.2.1.25.2.1.2':  # RAM type
            mem_used = int(used[i][1])
            mem_size = int(size[i][1])
            mem_percent = (mem_used / mem_size) * 100
            return mem_percent
    print("Could not find RAM memory usage")
    return None

if __name__ == "__main__":
    host = '192.168.237.190' 
    community = 'ganeshpawar09'

    cpu = get_cpu_load(host, community)
    if cpu is not None:
        print(f"CPU Load (avg across cores): {cpu:.2f}%")

    memory = get_memory_usage(host, community)
    if memory is not None:
        print(f"Memory Usage: {memory:.2f}%")
