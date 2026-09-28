import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict
from app.core.database import async_session_maker
from app.models.system_config import SystemConfig
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

async def get_mgmt_iface() -> str:
    async with async_session_maker() as session:
        result = await session.execute(select(SystemConfig).where(SystemConfig.key == "MGMT_IFACE"))
        record = result.scalars().first()
        return record.value if record else "eth0"

async def run_nmap_scan(target_subnet: str) -> List[Dict]:
    """Runs an active Nmap scan (OS and Ports) against a subnet."""
    mgmt_iface = await get_mgmt_iface()
    logger.info(f"Starting active Nmap discovery on {target_subnet} via {mgmt_iface}")
    cmd = ["nmap", "-e", mgmt_iface, "-O", "-sV", "-p", "22,23,80,443,161", "-oX", "/tmp/nmap_out.xml", target_subnet]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        return parse_nmap_xml("/tmp/nmap_out.xml")
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return []

def parse_nmap_xml(xml_file: str) -> List[Dict]:
    devices = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            if host.find("status").get("state") != "up":
                continue
                
            ip = host.find("address").get("addr")
            mac = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "mac":
                    mac = addr.get("addr")
            
            os_match = "Unknown"
            os_element = host.find("os")
            if os_element is not None:
                os_match_el = os_element.find("osmatch")
                if os_match_el is not None:
                    os_match = os_match_el.get("name")
                    
            ports = []
            device_type = "endpoint"
            for port in host.findall(".//port"):
                portid = port.get("portid")
                state = port.find("state").get("state")
                if state == "open":
                    ports.append(portid)
                    service = port.find("service")
                    if service is not None:
                        product = service.get("product", "").lower()
                        if "cisco" in product or "router" in product or "switch" in product:
                            device_type = "network_equipment"
            
            if "Router" in os_match or "Switch" in os_match:
                device_type = "network_equipment"
            elif "Linux" in os_match and ("161" in ports or "22" in ports) and mac is None: # Router GW heuristic
                device_type = "network_equipment"

            devices.append({
                "ip": ip,
                "mac": mac,
                "os_version": os_match,
                "open_ports": ports,
                "device_type": device_type
            })
    except Exception as e:
        logger.error(f"Error parsing XML: {e}")
    return devices
