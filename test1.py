import time
from datetime import datetime
import matplotlib.pyplot as plt
from pysnmp.hlapi import *

# SNMP GET request
def snmp_get(oid, host, community='public', port=161):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community, mpModel=0),
               UdpTransportTarget((host, port)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )
    if errorIndication:
        print(f"SNMP GET Error: {errorIndication}")
        return None
    elif errorStatus:
        print(f"SNMP GET Error: {errorStatus.prettyPrint()} at {errorIndex}")
        return None
    else:
        for varBind in varBinds:
            return varBind[1]
    return None

# SNMP WALK request
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
            print(f"SNMP WALK Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"SNMP WALK Error: {errorStatus.prettyPrint()} at {errorIndex}")
            break
        else:
            for varBind in varBinds:
                result.append(varBind)
    return result

# Get average CPU load
def get_cpu_load(host, community='public'):
    cpu_loads = snmp_walk('1.3.6.1.2.1.25.3.3.1.2', host, community)
    if not cpu_loads:
        return None
    loads = [int(x[1]) for x in cpu_loads]
    return sum(loads) / len(loads)

# Get memory usage percentage
def get_memory_usage(host, community='public'):
    total_mem = snmp_get('1.3.6.1.2.1.25.2.2.0', host, community)
    if total_mem is None:
        return None

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
            return (mem_used / mem_size) * 100
    return None

# Live monitor and plot
def live_monitor(host, community='public', interval=5, duration=60):
    timestamps = []
    cpu_data = []
    mem_data = []

    plt.ion()
    fig, ax = plt.subplots(figsize=(10, 6))

    start_time = time.time()

    while time.time() - start_time < duration:
        now = datetime.now().strftime("%H:%M:%S")
        cpu = get_cpu_load(host, community)
        mem = get_memory_usage(host, community)

        if cpu is not None and mem is not None:
            print(f"[{now}] CPU: {cpu:.2f}% | Memory: {mem:.2f}%")
            timestamps.append(now)
            cpu_data.append(cpu)
            mem_data.append(mem)

            ax.clear()
            ax.plot(timestamps, cpu_data, label='CPU Usage (%)', marker='o')
            ax.plot(timestamps, mem_data, label='Memory Usage (%)', marker='s')
            ax.set_xlabel("Time")
            ax.set_ylabel("Usage (%)")
            ax.set_title("Live CPU and Memory Usage")
            ax.legend()
            ax.grid(True)
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.pause(0.1)

        time.sleep(interval)

    plt.ioff()
    plt.show()

if __name__ == "__main__":
    host = '192.168.237.189'         # Replace with your SNMP device IP
    community = 'ganeshpawar09'      # Replace with your community string
    live_monitor(host, community, interval=5, duration=120)  # Duration in seconds
