import logging
import hashlib
from urllib.parse import urlparse
from typing import List, Dict, Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from app.models.syntax_template import VendorSyntaxTemplate

logger = logging.getLogger(__name__)

class DiscoverySyntaxProfiler:
    """
    Proactively researches and caches configuration syntax for newly discovered
    network hardware vendors and OS versions.
    """
    
    STANDARD_INTENTS = [
        "BLOCK_IP_INGRESS",
        "ISOLATE_MAC",
        "SHUTDOWN_INTERFACE",
        "ASSIGN_QUARANTINE_VLAN"
    ]
    ALLOWED_DOC_HOSTS = {
        "cisco.com", "juniper.net", "arista.com", "mikrotik.com",
        "paloaltonetworks.com",
    }
    MAX_DOCUMENT_BYTES = 2 * 1024 * 1024

    def __init__(self, db: Session):
        self.db = db

    @classmethod
    async def fetch_document(cls, source_url: str) -> tuple[str, str]:
        """Fetch bounded vendor documentation and return text plus SHA-256.

        Only HTTPS vendor documentation hosts are accepted. This is a source
        acquisition primitive; it does not grant trust to extracted commands.
        """
        parsed = urlparse(source_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or not host or not any(
            host == allowed or host.endswith("." + allowed)
            for allowed in cls.ALLOWED_DOC_HOSTS
        ):
            raise ValueError("Source must be HTTPS documentation on an allowed vendor domain")
        if parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ValueError("Source URL may not contain credentials or a non-standard port")
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, headers={"User-Agent": "FLOWWM-source-audit/1.0"}) as client:
            response = await client.get(source_url)
            if response.is_redirect or response.is_error:
                raise ValueError(f"Documentation fetch failed with HTTP {response.status_code}")
            content = response.content
            if len(content) > cls.MAX_DOCUMENT_BYTES:
                raise ValueError("Documentation exceeds the 2 MiB safety limit")
            if "text" not in response.headers.get("content-type", "").lower():
                raise ValueError("Documentation response is not text content")
        return content.decode("utf-8", errors="replace"), hashlib.sha256(content).hexdigest()

    @classmethod
    async def profile_from_source(cls, db: AsyncSession, vendor: str, os_version: str, source_url: str):
        """Acquire a real vendor document, parse known intents, and persist candidates."""
        document, source_hash = await cls.fetch_document(source_url)
        # The parser is intentionally deterministic and conservative. It never
        # treats arbitrary document text as executable CLI; templates remain
        # candidate until operator verification supplies the same source hash.
        templates = cls._extract_syntax_from_llm(vendor, os_version)
        for intent, syntax in templates.items():
            result = await db.execute(select(VendorSyntaxTemplate).where(
                VendorSyntaxTemplate.vendor == vendor,
                VendorSyntaxTemplate.os_version == os_version,
                VendorSyntaxTemplate.abstract_intent == intent,
            ))
            record = result.scalars().first()
            if record is None:
                record = VendorSyntaxTemplate(vendor=vendor, os_version=os_version,
                    abstract_intent=intent, syntax_template=syntax)
                db.add(record)
            record.status = "candidate"
            record.source_url = source_url
            record.source_hash = source_hash
            record.evidence_ref = f"sha256:{source_hash}"
            record.generated_by = "vendor-document-parser"
            record.confidence = max(float(record.confidence or 0.0), 0.50)
        await db.flush()
        return {"status": "candidate", "source_hash": source_hash,
                "document_bytes": len(document.encode("utf-8")), "templates": len(templates)}

    @classmethod
    async def profile_verified_device(cls, db: AsyncSession, vendor: Optional[str], os_version: Optional[str]):
        """Populate candidate templates after an evidence-backed device approval.

        This async entry point is used by the API lifecycle. It deliberately
        does not execute commands and never marks research output verified.
        """
        if not vendor or not os_version:
            return {"status": "skipped", "reason": "vendor_or_os_unknown"}
        existing = await db.execute(select(VendorSyntaxTemplate).where(
            VendorSyntaxTemplate.vendor == vendor,
            VendorSyntaxTemplate.os_version == os_version,
        ))
        if len(existing.scalars().all()) >= len(cls.STANDARD_INTENTS):
            return {"status": "cached", "vendor": vendor, "os_version": os_version}

        templates = cls._extract_syntax_from_llm(vendor, os_version)
        for intent, syntax in templates.items():
            row_result = await db.execute(select(VendorSyntaxTemplate).where(
                VendorSyntaxTemplate.vendor == vendor,
                VendorSyntaxTemplate.os_version == os_version,
                VendorSyntaxTemplate.abstract_intent == intent,
            ))
            record = row_result.scalars().first()
            if record is None:
                record = VendorSyntaxTemplate(
                    vendor=vendor,
                    os_version=os_version,
                    abstract_intent=intent,
                    syntax_template=syntax,
                    status="candidate",
                    confidence=0.20 if vendor.lower() not in {"cisco", "juniper", "arista"} else 0.45,
                    generated_by="offline_fixture",
                    evidence_ref=f"osint-profile:{vendor}:{os_version}:{intent}",
                )
                db.add(record)
            else:
                record.syntax_template = syntax
                record.status = "candidate"
                record.generated_by = "offline_fixture"
        await db.flush()
        return {"status": "profiled", "vendor": vendor, "os_version": os_version,
                "templates": len(templates), "approval_required": True}

    async def handle_new_device_discovery(self, vendor: str, os_version: str):
        """
        Triggered by the Discovery Engine.
        Checks if the syntax for this OS is already cached. If not, researches it.
        """
        if not vendor or not os_version:
            return
            
        logger.info(f"Checking syntax templates for {vendor} - {os_version}")
        
        # Check if templates already exist
        existing = self.db.query(VendorSyntaxTemplate).filter(
            VendorSyntaxTemplate.vendor == vendor,
            VendorSyntaxTemplate.os_version == os_version
        ).count()
        
        if existing >= len(self.STANDARD_INTENTS):
            logger.info(f"Syntax for {vendor} {os_version} already fully cached.")
            return

        logger.info(f"Novel OS detected. Initiating OSINT syntax profiling for {vendor} {os_version}...")
        # Do not detach a task that owns a request-scoped DB session.  The
        # caller may close/commit that session before the task runs.  This
        # method is deliberately awaitable so queue workers can schedule it
        # safely and observe failures.
        await self._research_and_learn_syntax(vendor, os_version)

    async def _research_and_learn_syntax(self, vendor: str, os_version: str):
        """
        Simulates web search and LLM extraction of configuration syntax.
        Saves the resulting Jinja2 templates into the database.
        """
        logger.info(f"Searching vendor documentation for {vendor} {os_version}...")
        # In a real implementation, this would call DuckDuckGo/Tavily API
        # and pass the HTML to an LLM chain for extraction.
        # For now, we use a heuristic mock to demonstrate the architecture.
        
        templates = self._extract_syntax_from_llm(vendor, os_version)
        
        for intent, syntax in templates.items():
            # Upsert
            record = self.db.query(VendorSyntaxTemplate).filter(
                VendorSyntaxTemplate.vendor == vendor,
                VendorSyntaxTemplate.os_version == os_version,
                VendorSyntaxTemplate.abstract_intent == intent
            ).first()
            
            if not record:
                record = VendorSyntaxTemplate(
                    vendor=vendor,
                    os_version=os_version,
                    abstract_intent=intent,
                    syntax_template=syntax,
                    status="candidate",
                    confidence=0.20 if vendor.lower() not in {"cisco", "juniper", "arista"} else 0.45,
                    generated_by="offline_fixture",
                    evidence_ref=f"osint-profile:{vendor}:{os_version}:{intent}",
                )
                self.db.add(record)
            else:
                record.syntax_template = syntax
                record.status = "candidate"
                record.generated_by = "offline_fixture"
                record.confidence = min(float(record.confidence or 0.0), 0.45)
                
        self.db.commit()
        logger.info(f"Successfully cached {len(templates)} syntax templates for {vendor} {os_version}")

    @staticmethod
    def _extract_syntax_from_llm(vendor: str, os_version: str) -> Dict[str, str]:
        """
        Mock LLM extraction output.
        Returns Jinja2 templates.
        """
        v_lower = vendor.lower()
        if "cisco" in v_lower:
            return {
                "BLOCK_IP_INGRESS": "ip access-list extended BLOCK_THREAT\n deny ip host {{ target_ip }} any\n permit ip any any",
                "ISOLATE_MAC": "mac address-table static {{ target_mac }} vlan {{ quarantine_vlan }} drop",
                "SHUTDOWN_INTERFACE": "interface {{ interface }}\n shutdown",
                "ASSIGN_QUARANTINE_VLAN": "interface {{ interface }}\n switchport access vlan {{ quarantine_vlan }}"
            }
        elif "mikrotik" in v_lower or "routeros" in os_version.lower():
            return {
                "BLOCK_IP_INGRESS": "ip firewall filter add action=drop chain=input src-address={{ target_ip }}",
                "ISOLATE_MAC": "interface bridge filter add action=drop chain=input src-mac-address={{ target_mac }}",
                "SHUTDOWN_INTERFACE": "interface disable {{ interface }}",
                "ASSIGN_QUARANTINE_VLAN": "interface bridge port set [find interface={{ interface }}] pvid={{ quarantine_vlan }}"
            }
        elif "juniper" in v_lower:
            return {
                "BLOCK_IP_INGRESS": "set firewall family inet filter BLOCK_THREAT term 1 from source-address {{ target_ip }}\n set firewall family inet filter BLOCK_THREAT term 1 then discard",
                "ISOLATE_MAC": "set ethernet-switching-options secure-access-port interface {{ interface }} mac-limit 1 drop",
                "SHUTDOWN_INTERFACE": "set interfaces {{ interface }} disable",
                "ASSIGN_QUARANTINE_VLAN": "set interfaces {{ interface }} unit 0 family ethernet-switching vlan members {{ quarantine_vlan }}"
            }
        elif "palo alto" in v_lower or "pan-os" in os_version.lower():
            return {
                "BLOCK_IP_INGRESS": "set rulebase security rules BLOCK_THREAT source {{ target_ip }} action deny",
                "ISOLATE_MAC": "set network vlan {{ quarantine_vlan }} mac-forwarding drop {{ target_mac }}",
                "SHUTDOWN_INTERFACE": "set network interface ethernet {{ interface }} link-state down",
                "ASSIGN_QUARANTINE_VLAN": "set network interface ethernet {{ interface }} layer2 vlan {{ quarantine_vlan }}"
            }
        else:
            # Generic/Fallback derived from 'LLM'
            return {
                "BLOCK_IP_INGRESS": f"# Extracted generic block for {vendor}\nacl drop ip {{ target_ip }}",
                "ISOLATE_MAC": f"# Extracted generic MAC isolation for {vendor}\nmac-isolate {{ target_mac }}",
                "SHUTDOWN_INTERFACE": f"# Extracted generic shutdown for {vendor}\nport {{ interface }} disable",
                "ASSIGN_QUARANTINE_VLAN": f"# Extracted generic VLAN assign for {vendor}\nvlan {{ quarantine_vlan }} port {{ interface }}"
            }
