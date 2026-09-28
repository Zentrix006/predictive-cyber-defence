import json
import sys
import hashlib
from pathlib import Path
from typing import List, Dict, Set
from canonical_schema import CampaignManifest, CanonicalEvent, DeviceRecord, TopologyEdge

def validate_partition_boundaries(manifests: List[CampaignManifest]) -> bool:
    """Fail closed if a capture/campaign/site is reused across partitions."""
    seen = {}
    passed = True
    for manifest in manifests:
        for key, values in (("campaign", [manifest.campaign_id]), ("site", [manifest.site_id]),
                             ("capture", manifest.captures_included)):
            for value in values:
                prior = seen.get((key, value))
                if prior and prior != manifest.partition:
                    print(f"  [FAIL] {key} {value} crosses partitions: {prior} -> {manifest.partition}")
                    passed = False
                seen[(key, value)] = manifest.partition
    return passed

def hash_file(filepath: Path) -> str:
    sha256 = hashlib.sha256()
    if not filepath.exists():
        return ""
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def validate_dataset_manifests(manifests: List[CampaignManifest], dataset_root: Path) -> bool:
    passed = validate_partition_boundaries(manifests)
    
    for m in manifests:
        campaign_passed = True
        print(f"\n[VALIDATING CAMPAIGN]: {m.campaign_id}")
        
        # 1. Check Artifact Files and Hashes
        artifacts = {
            "event_file": m.event_file,
            "device_file": m.device_file,
            "topology_file": m.topology_file
        }
        
        # Artifact hashes are separate from capture hashes. Keeping these
        # namespaces distinct prevents a PCAP digest being reused for JSON.
        for name, rel_path in artifacts.items():
            if Path(rel_path).is_absolute() or ".." in Path(rel_path).parts:
                print(f"  [FAIL] {name} path escapes dataset root: {rel_path}")
                passed = campaign_passed = False
                continue
            full_path = dataset_root / rel_path
            if not full_path.exists():
                print(f"  [FAIL] {name} path does not exist: {full_path}")
                passed = campaign_passed = False
                continue
            declared_hash = m.artifact_hashes.get(name)
            if not declared_hash or len(declared_hash) != 64:
                print(f"  [FAIL] {name} is missing a valid 64-character SHA-256 hash in artifact_hashes.")
                passed = campaign_passed = False
                continue
                
            actual_hash = hash_file(full_path)
            if actual_hash != declared_hash:
                print(f"  [FAIL] {name} hash mismatch. Expected {declared_hash}, got {actual_hash}")
                passed = campaign_passed = False
                continue
                
            print(f"  [PASS] {name} hash verified: {actual_hash}")

        # If files exist and hashes pass, perform deep reference validation
        if not campaign_passed:
            continue
            
        print("  [VALIDATING REFERENCES]...")
        
        # Load JSON records
        with open(dataset_root / m.device_file, "r") as f:
            device_records = [DeviceRecord.model_validate(json.loads(line)) for line in f if line.strip()]
            device_ids = {d.device_id for d in device_records}
            
        with open(dataset_root / m.event_file, "r") as f:
            events = [CanonicalEvent.model_validate(json.loads(line)) for line in f if line.strip()]
            
        with open(dataset_root / m.topology_file, "r") as f:
            edges = [TopologyEdge.model_validate(json.loads(line)) for line in f if line.strip()]

        if not events:
            print("  [FAIL] Campaign has no canonical events")
            passed = campaign_passed = False
            
        # Validate Event -> Device references
        derived_stages = set()
        for ev in events:
            # Check capture_id, campaign_id, site_id matching manifest
            if ev.campaign_id != m.campaign_id or ev.site_id != m.site_id:
                print(f"  [FAIL] Event {ev.event_id} campaign/site does not match manifest")
                passed = campaign_passed = False
            if ev.capture_id not in m.captures_included:
                print(f"  [FAIL] Event {ev.event_id} references capture outside manifest: {ev.capture_id}")
                passed = campaign_passed = False
            if ev.source_file_hash != m.capture_hashes.get(ev.capture_id):
                print(f"  [FAIL] Event {ev.event_id} source hash does not match capture hash")
                passed = campaign_passed = False
            if ev.label_is_unknown and (ev.mitre_stage or ev.label != "unknown"):
                print(f"  [FAIL] Event {ev.event_id} marks unknown labels but carries a known stage/label")
                passed = campaign_passed = False
            
            src_dev = ev.src_device_id
            dst_dev = ev.dst_device_id
            if src_dev and src_dev not in device_ids:
                print(f"  [FAIL] Event {ev.event_id} references unknown src_device_id: {src_dev}")
                passed = campaign_passed = False
            if dst_dev and dst_dev not in device_ids:
                print(f"  [FAIL] Event {ev.event_id} references unknown dst_device_id: {dst_dev}")
                passed = campaign_passed = False
                
            stage = ev.mitre_stage
            if stage:
                derived_stages.add(stage)
                
        # Validate Topology -> Device references
        for edge in edges:
            if edge.source_device not in device_ids:
                print(f"  [FAIL] Edge references unknown source_device: {edge.source_device}")
                passed = campaign_passed = False
            source = next((d for d in device_records if d.device_id == edge.source_device), None)
            target = next((d for d in device_records if d.device_id == edge.destination_device), None)
            if source and target and (source.identity_status == "unknown" or target.identity_status == "unknown"):
                print(f"  [FAIL] Edge {edge.source_device}->{edge.destination_device} uses unknown device identity")
                passed = campaign_passed = False
            if edge.destination_device not in device_ids:
                print(f"  [FAIL] Edge references unknown destination_device: {edge.destination_device}")
                passed = campaign_passed = False

        # Validate stages_present matches derived_stages
        declared_stages = set(m.stages_present)
        if declared_stages != derived_stages:
            print(f"  [FAIL] Declared stages {declared_stages} do not match stages derived from events {derived_stages}")
            passed = campaign_passed = False
            
    return passed

if __name__ == "__main__":
    # In execution, this would parse real inputs.
    print("Manifest Validator ready.")
