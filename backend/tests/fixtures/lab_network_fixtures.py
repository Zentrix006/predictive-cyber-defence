import json

# Simulated SNMP, LLDP, CDP, ARP, and CLI telemetry outputs for lab devices
LAB_CORE_SW01_TELEMETRY = {
    "hostname": "lab-core-sw01",
    "vendor": "cisco",
    "model": "Catalyst 9300",
    "management_ip": "10.100.10.1",
    "mac_address": "00:1A:2B:3C:4D:5E",
    "interfaces": [
        {"name": "GigabitEthernet1/0/1", "status": "up", "vlan": 20},
        {"name": "GigabitEthernet1/0/2", "status": "up", "vlan": 30},
        {"name": "GigabitEthernet1/0/24", "status": "up", "vlan": 10, "type": "trunk"}
    ],
    "cdp_neighbors": [
        {"local_int": "GigabitEthernet1/0/24", "neighbor": "lab-border-gw01", "port": "ge-0/0/0"}
    ],
    "mac_table": [
        {"mac": "AA:BB:CC:DD:EE:01", "vlan": 20, "interface": "GigabitEthernet1/0/1"},
        {"mac": "AA:BB:CC:DD:EE:02", "vlan": 30, "interface": "GigabitEthernet1/0/2"}
    ],
    "vlans": [
        {"id": 10, "name": "Management"},
        {"id": 20, "name": "Production"},
        {"id": 30, "name": "IoT"},
        {"id": 999, "name": "Quarantine"}
    ]
}

LAB_BORDER_GW01_TELEMETRY = {
    "hostname": "lab-border-gw01",
    "vendor": "juniper",
    "model": "SRX340",
    "management_ip": "10.100.10.2",
    "mac_address": "00:5E:4D:3C:2B:1A",
    "interfaces": [
        {"name": "ge-0/0/0", "status": "up", "vlan": 10, "type": "trunk"},
        {"name": "ge-0/0/1", "status": "up"}
    ],
    "lldp_neighbors": [
        {"local_int": "ge-0/0/0", "neighbor": "lab-core-sw01", "port": "GigabitEthernet1/0/24"}
    ],
    "routing_table": [
        {"network": "10.100.20.0/24", "next_hop": "10.100.10.1"},
        {"network": "10.100.30.0/24", "next_hop": "10.100.10.1"}
    ]
}

LAB_DB_SRV01_TELEMETRY = {
    "hostname": "lab-db-srv01",
    "os": "Linux",
    "ip_address": "10.100.20.10",
    "mac_address": "AA:BB:CC:DD:EE:01",
    "arp_cache": [
        {"ip": "10.100.20.1", "mac": "00:1A:2B:3C:4D:5E"}
    ]
}

LAB_WORKSTATION_04_TELEMETRY = {
    "hostname": "lab-workstation-04",
    "os": "Windows",
    "ip_address": "10.100.20.55",
    "mac_address": "AA:BB:CC:DD:EE:11"
}

LAB_IOT_CAM02_TELEMETRY = {
    "hostname": "unknown",
    "vendor": "unknown",
    "ip_address": "10.100.30.88",
    "mac_address": "AA:BB:CC:DD:EE:02"
}

def get_all_fixtures():
    return [
        LAB_CORE_SW01_TELEMETRY,
        LAB_BORDER_GW01_TELEMETRY,
        LAB_DB_SRV01_TELEMETRY,
        LAB_WORKSTATION_04_TELEMETRY,
        LAB_IOT_CAM02_TELEMETRY
    ]
