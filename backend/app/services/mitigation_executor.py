import logging
import ipaddress
import re
from sqlalchemy.orm import Session
from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment
from app.models.syntax_template import VendorSyntaxTemplate
from app.models.asset import Asset
from app.models.system_config import SystemConfig
import ipaddress

logger = logging.getLogger(__name__)

class IncidentMitigationExecutor:
    """
    Executes rapid containment by resolving abstract mitigation intents
    into concrete device commands using pre-cached OSINT syntax.
    """
    def __init__(self, db: Session):
        self.db = db

    _INTENTS = {
        "BLOCK_IP_INGRESS", "ISOLATE_MAC", "SHUTDOWN_INTERFACE",
        "ASSIGN_QUARANTINE_VLAN",
    }
    _SAFE_CONTEXT_KEYS = {"target_ip", "target_mac", "interface", "quarantine_vlan"}

    @staticmethod
    def _validate_context(intent: str, context: dict) -> None:
        if intent not in IncidentMitigationExecutor._INTENTS:
            raise ValueError("Unsupported mitigation intent")
        if not isinstance(context, dict) or set(context) - IncidentMitigationExecutor._SAFE_CONTEXT_KEYS:
            raise ValueError("Context contains unsupported fields")
        if "target_ip" in context:
            ipaddress.ip_address(str(context["target_ip"]))
        if "target_mac" in context and not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", str(context["target_mac"])):
            raise ValueError("Invalid target MAC")
        if "interface" in context and not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,64}", str(context["interface"])):
            raise ValueError("Invalid interface")
        if "quarantine_vlan" in context:
            vlan = int(context["quarantine_vlan"])
            if not 1 <= vlan <= 4094:
                raise ValueError("Invalid quarantine VLAN")

    async def execute_mitigation(self, asset_id: str, intent: str, context: dict) -> dict:
        """
        Fast-path incident response execution.
        """
        asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
        mgmt_subnet_record = self.db.query(SystemConfig).filter(SystemConfig.key == "MGMT_SUBNET").first()
        try:
            subnet_val = mgmt_subnet_record.value if mgmt_subnet_record else "172.20.20.0/24"
            if not ipaddress.ip_address(asset.ip_address) in ipaddress.ip_network(subnet_val):
                logger.error(f"Asset IP {asset.ip_address} is outside Management Subnet {subnet_val}")
                return {"status": "error", "message": "Target IP outside MGMT_SUBNET"}
        except Exception as e:
            return {"status": "error", "message": f"Invalid IP validation: {e}"}
        if not asset:
            logger.error(f"Asset {asset_id} not found.")
            return {"status": "error", "message": "Asset not found"}
            
        vendor = asset.vendor or "Unknown"
        os_version = asset.os_version or "Unknown"
        
        logger.info(f"Looking up cached syntax for {vendor} {os_version} -> {intent}")
        
        template_record = self.db.query(VendorSyntaxTemplate).filter(
            VendorSyntaxTemplate.vendor == vendor,
            VendorSyntaxTemplate.os_version == os_version,
            VendorSyntaxTemplate.abstract_intent == intent
        ).first()
        
        if not template_record:
            logger.warning(f"No cached syntax found for {vendor} {os_version} {intent}. Mitigation failed.")
            return {"status": "error", "message": "Missing syntax template. Was discovery profiler executed?"}
            
        try:
            subnet_val = mgmt_subnet_record.value if mgmt_subnet_record else "172.20.20.0/24"
            self._validate_context(intent, context)
            env = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)
            compiled_script = env.from_string(template_record.syntax_template).render(**context)
        except Exception as e:
            logger.error(f"Failed to render Jinja2 template: {e}")
            return {"status": "error", "message": f"Template compilation failed: {e}"}
            
        # Here we would normally push the script via Netmiko/Napalm to the device's management IP.
        # For demonstration and safety, we dry-run/log the output.
        # Research/OSINT output is never executable until an operator verifies
        # its source and the normal config-planning/canary path approves it.
        pending_approval = template_record.status != "verified"
        logger.info(f"--- MITIGATION COMPILED FOR {asset.ip_address} ---")
        logger.info(f"\n{compiled_script}\n")
        logger.info("-------------------------------------------------")
        
        return {
            "status": "pending_approval" if pending_approval else "success",
            "execution_allowed": not pending_approval,
            "approval_required": pending_approval,
            "template_status": template_record.status,
            "template_evidence_ref": template_record.evidence_ref,
            "compiled_script": compiled_script,
            "device": {"vendor": vendor, "os_version": os_version, "ip": asset.ip_address}
        }
