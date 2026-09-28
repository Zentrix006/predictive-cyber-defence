"""
Evidence and Device Learning Service (Phase 1)
Append-only evidence ingestion, multi-source confidence fusion, operator verification workflows,
and topology edge reconciliation.
"""
from datetime import datetime, timezone, timedelta
import hashlib
import json
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID

from sqlalchemy import select, and_, or_, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovery_evidence import (
    DeviceIdentity,
    DiscoveryObservation,
    DeviceSnapshot,
    TopologyEdge,
    DeviceLifecycleStatus,
    EdgeRelationshipType,
    EdgeLifecycleStatus,
)
from app.schemas.discovery_evidence import (
    DiscoveryObservationCreate,
    DeviceIdentityCreate,
    DeviceVerificationAction,
    DeviceSnapshotCreate,
    TopologyEdgeCreate,
)

# Standard protocol reliability baselines
PROTOCOL_CONFIDENCE_BASE: Dict[str, float] = {
    "snmpv3": 0.95,
    "snmpv2c": 0.85,
    "lldp": 0.92,
    "cdp": 0.90,
    "dhcp": 0.85,
    "reverse_dns": 0.75,
    "dns": 0.70,
    "mdns": 0.65,
    "arp": 0.65,
    "netflow": 0.55,
    "flow_heuristic": 0.50,
}


def calculate_fusion_confidence(confidences: List[float]) -> float:
    """
    Bayesian multi-source independent evidence fusion:
    C_fused = 1 - Prod(1 - c_i)
    Ensures that multiple independent corroborating sources yield higher confidence.
    """
    if not confidences:
        return 0.50
    prod = 1.0
    for c in confidences:
        c_clamped = max(0.01, min(0.98, c))
        prod *= (1.0 - c_clamped)
    fused = 1.0 - prod
    return round(min(0.99, max(0.10, fused)), 4)


class EvidenceService:
    """
    Core service managing append-only discovery observations, verified device identities,
    and topological edge lifecycles.
    """

    @staticmethod
    async def get_or_create_device_identity(
        db: AsyncSession,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        device_role: str = "unknown",
        site_zone: str = "unknown",
    ) -> DeviceIdentity:
        """
        Resolve device identity by hardware MAC first, then IP, then hostname.
        If no match exists, create a provisional DeviceIdentity.
        """
        now = datetime.now(timezone.utc)
        device: Optional[DeviceIdentity] = None

        # 1. Match by primary MAC
        if mac:
            mac_clean = mac.lower().strip()
            q = select(DeviceIdentity).where(
                or_(
                    DeviceIdentity.primary_mac == mac_clean,
                    DeviceIdentity.macs.contains([mac_clean]),
                )
            )
            res = await db.execute(q)
            device = res.scalars().first()

        # 2. Match by primary IP if not found
        if not device and ip:
            ip_clean = ip.strip()
            q = select(DeviceIdentity).where(
                or_(
                    DeviceIdentity.primary_ip == ip_clean,
                    DeviceIdentity.ips.contains([ip_clean]),
                )
            )
            res = await db.execute(q)
            device = res.scalars().first()

        # 3. Match by hostname if not found
        if not device and hostname:
            host_clean = hostname.strip().lower()
            q = select(DeviceIdentity).where(
                DeviceIdentity.hostname == host_clean
            )
            res = await db.execute(q)
            device = res.scalars().first()

        # If existing, update last seen and merge any new IP/MAC
        if device:
            device.last_seen = now
            if ip and ip not in device.ips:
                device.ips = list(device.ips) + [ip]
            if mac and mac.lower() not in device.macs:
                device.macs = list(device.macs) + [mac.lower()]
            if hostname and not device.hostname:
                device.hostname = hostname.lower()
            if vendor and not device.vendor:
                device.vendor = vendor
            if device_role != "unknown" and device.device_role == "unknown":
                device.device_role = device_role
            await db.flush()
            return device

        # Create new provisional device
        macs_list = [mac.lower()] if mac else []
        ips_list = [ip] if ip else []
        device = DeviceIdentity(
            primary_ip=ip,
            primary_mac=mac.lower() if mac else None,
            ips=ips_list,
            macs=macs_list,
            hostname=hostname.lower() if hostname else None,
            vendor=vendor,  # null if unknown, never invented
            device_role=device_role,
            site_zone=site_zone,
            status=DeviceLifecycleStatus.PROVISIONAL.value,
            confidence=0.50,
            first_seen=now,
            last_seen=now,
        )
        db.add(device)
        await db.flush()
        return device

    @staticmethod
    async def record_observation(
        db: AsyncSession,
        obs_in: DiscoveryObservationCreate,
    ) -> DiscoveryObservation:
        """
        Record an immutable discovery observation (append-only).
        Resolves or updates the associated device identity and recalculates fused confidence.
        """
        now = datetime.now(timezone.utc)
        source_key = obs_in.source.lower().strip()
        default_conf = PROTOCOL_CONFIDENCE_BASE.get(source_key, 0.50)
        confidence = obs_in.confidence if obs_in.confidence != 0.5 else default_conf

        # Extract normalized fields
        fields = obs_in.normalized_fields or {}
        ip = fields.get("ip")
        mac = fields.get("mac")
        hostname = fields.get("hostname")
        vendor = fields.get("vendor")
        role = fields.get("role", "unknown")
        zone = fields.get("zone", "unknown")

        device_id = obs_in.device_id
        if not device_id and (ip or mac or hostname):
            device = await EvidenceService.get_or_create_device_identity(
                db, ip=ip, mac=mac, hostname=hostname, vendor=vendor, device_role=role, site_zone=zone
            )
            device_id = device.id

        # Insert immutable observation
        observation = DiscoveryObservation(
            device_id=device_id,
            source=source_key,
            timestamp=obs_in.timestamp or now,
            collector=obs_in.collector,
            raw_evidence_ref=obs_in.raw_evidence_ref,
            normalized_fields=fields,
            confidence=confidence,
            auth_method=obs_in.auth_method,
            operator_id=obs_in.operator_id,
        )
        db.add(observation)
        await db.flush()

        # Recalculate device confidence based on observations
        if device_id:
            q_obs = select(DiscoveryObservation.confidence).where(
                DiscoveryObservation.device_id == device_id
            )
            res = await db.execute(q_obs)
            all_confs = res.scalars().all()
            fused_conf = calculate_fusion_confidence(list(all_confs))

            q_dev = select(DeviceIdentity).where(DeviceIdentity.id == device_id)
            res_dev = await db.execute(q_dev)
            dev = res_dev.scalars().first()
            if dev:
                dev.confidence = fused_conf
                dev.last_seen = now
                if vendor and not dev.vendor:
                    dev.vendor = vendor
                if fields.get("model") and not dev.model:
                    dev.model = fields["model"]
                if role != "unknown" and dev.device_role == "unknown":
                    dev.device_role = role
                if ip and ip not in dev.ips:
                    dev.ips = list(dev.ips) + [ip]
                if mac and mac.lower() not in dev.macs:
                    dev.macs = list(dev.macs) + [mac.lower()]
                await db.flush()

        return observation

    @staticmethod
    async def verify_device_identity(
        db: AsyncSession,
        device_id: UUID,
        action: DeviceVerificationAction,
    ) -> DeviceIdentity:
        """
        Operator-driven verification workflow:
        - approve: promotes provisional -> verified
        - reject: marks rejected
        - merge: merges into target_device_id
        """
        now = datetime.now(timezone.utc)
        q = select(DeviceIdentity).where(DeviceIdentity.id == device_id)
        res = await db.execute(q)
        device = res.scalars().first()
        if not device:
            raise ValueError(f"Device {device_id} not found")

        action_type = action.action.lower().strip()

        if action_type == "approve":
            device.status = DeviceLifecycleStatus.VERIFIED.value
            device.verified_at = now
            device.verified_by = action.verified_by
            if action.vendor_override:
                device.vendor = action.vendor_override
            if action.role_override:
                device.device_role = action.role_override
            if action.notes:
                device.notes = action.notes
            device.confidence = max(device.confidence, 0.90)

        elif action_type == "reject":
            device.status = DeviceLifecycleStatus.REJECTED.value
            device.verified_at = now
            device.verified_by = action.verified_by
            if action.notes:
                device.notes = action.notes

        elif action_type == "merge":
            if not action.target_device_id:
                raise ValueError("target_device_id is required for merge action")
            q_target = select(DeviceIdentity).where(DeviceIdentity.id == action.target_device_id)
            res_target = await db.execute(q_target)
            target = res_target.scalars().first()
            if not target:
                raise ValueError(f"Target device {action.target_device_id} not found")

            # Merge IPs and MACs into target
            for ip in device.ips:
                if ip not in target.ips:
                    target.ips = list(target.ips) + [ip]
            for mac in device.macs:
                if mac not in target.macs:
                    target.macs = list(target.macs) + [mac]

            # Re-point observations to target
            await db.execute(
                update(DiscoveryObservation)
                .where(DiscoveryObservation.device_id == device.id)
                .values(device_id=target.id)
            )

            # Re-point topology edges
            await db.execute(
                update(TopologyEdge)
                .where(TopologyEdge.source_device_id == device.id)
                .values(source_device_id=target.id)
            )
            await db.execute(
                update(TopologyEdge)
                .where(TopologyEdge.destination_device_id == device.id)
                .values(destination_device_id=target.id)
            )

            device.status = DeviceLifecycleStatus.MERGED.value
            device.notes = f"Merged into {target.id} by {action.verified_by}"
            device.verified_at = now
            device.verified_by = action.verified_by

        else:
            raise ValueError(f"Unknown verification action: {action.action}")

        await db.flush()
        return device

    @staticmethod
    async def capture_device_snapshot(
        db: AsyncSession,
        snap_in: DeviceSnapshotCreate,
    ) -> DeviceSnapshot:
        """
        Record point-in-time configuration and interface state.
        """
        now = datetime.now(timezone.utc)
        payload_bytes = json.dumps({
            "interfaces": snap_in.interfaces,
            "vlans": snap_in.vlans_and_trunks,
            "routing": snap_in.routing_table,
            "neighbours": snap_in.neighbours,
        }, sort_keys=True).encode()
        calc_hash = hashlib.sha256(payload_bytes).hexdigest()
        config_hash = snap_in.configuration_hash or calc_hash

        snapshot = DeviceSnapshot(
            device_id=snap_in.device_id,
            interfaces=snap_in.interfaces,
            link_state=snap_in.link_state,
            vlans_and_trunks=snap_in.vlans_and_trunks,
            routing_table=snap_in.routing_table,
            neighbours=snap_in.neighbours,
            acl_metadata=snap_in.acl_metadata,
            enabled_services=snap_in.enabled_services,
            configuration_hash=config_hash,
            collected_at=now,
            source_observation_ids=snap_in.source_observation_ids,
        )
        db.add(snapshot)
        await db.flush()
        return snapshot

    @staticmethod
    async def reconcile_topology_edge(
        db: AsyncSession,
        edge_in: TopologyEdgeCreate,
    ) -> TopologyEdge:
        """
        Reconcile or insert an evidence-backed topology edge.
        If the edge exists, updates last_confirmed and confidence.
        """
        now = datetime.now(timezone.utc)
        q = select(TopologyEdge).where(
            and_(
                TopologyEdge.source_device_id == edge_in.source_device_id,
                TopologyEdge.destination_device_id == edge_in.destination_device_id,
                TopologyEdge.relationship_type == edge_in.relationship_type,
            )
        )
        res = await db.execute(q)
        edge = res.scalars().first()

        if edge:
            edge.last_confirmed = now
            edge.confidence = round(min(0.99, max(edge.confidence, edge_in.confidence)), 4)
            edge.status = EdgeLifecycleStatus.ACTIVE.value
            if edge_in.source_interface:
                edge.source_interface = edge_in.source_interface
            if edge_in.destination_interface:
                edge.destination_interface = edge_in.destination_interface
            if edge_in.vlan_id is not None:
                edge.vlan_id = edge_in.vlan_id
            await db.flush()
            return edge

        new_edge = TopologyEdge(
            source_device_id=edge_in.source_device_id,
            destination_device_id=edge_in.destination_device_id,
            relationship_type=edge_in.relationship_type,
            source_interface=edge_in.source_interface,
            destination_interface=edge_in.destination_interface,
            vlan_id=edge_in.vlan_id,
            evidence_source=edge_in.evidence_source,
            confidence=edge_in.confidence,
            status=EdgeLifecycleStatus.ACTIVE.value,
            first_seen=now,
            last_confirmed=now,
        )
        db.add(new_edge)
        await db.flush()
        return new_edge

    @staticmethod
    async def retire_stale_records(
        db: AsyncSession,
        device_ttl_hours: int = 72,
        edge_ttl_hours: int = 48,
    ) -> Dict[str, int]:
        """
        Transition unconfirmed provisional devices and inactive edges to RETIRED / STALE.
        """
        now = datetime.now(timezone.utc)
        dev_cutoff = now - timedelta(hours=device_ttl_hours)
        edge_cutoff = now - timedelta(hours=edge_ttl_hours)

        # Mark provisional devices past TTL as RETIRED
        dev_stmt = (
            update(DeviceIdentity)
            .where(
                and_(
                    DeviceIdentity.status == DeviceLifecycleStatus.PROVISIONAL.value,
                    DeviceIdentity.last_seen < dev_cutoff,
                )
            )
            .values(status=DeviceLifecycleStatus.RETIRED.value)
        )
        dev_res = await db.execute(dev_stmt)

        # Mark edges past TTL as STALE
        edge_stmt = (
            update(TopologyEdge)
            .where(
                and_(
                    TopologyEdge.status == EdgeLifecycleStatus.ACTIVE.value,
                    TopologyEdge.last_confirmed < edge_cutoff,
                )
            )
            .values(status=EdgeLifecycleStatus.STALE.value)
        )
        edge_res = await db.execute(edge_stmt)

        await db.flush()
        return {
            "retired_devices": dev_res.rowcount or 0,
            "stale_edges": edge_res.rowcount or 0,
        }
