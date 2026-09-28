import pytest
from app.services.epistemic_deception import EpistemicDeceptionOrchestrator, DeceptionSandboxInstance
from training.episodic_replay import EpisodicReplayBuffer


def test_sandbox_provisioning_catalog():
    orchestrator = EpistemicDeceptionOrchestrator()
    
    # SSH port 22 -> Cowrie
    sb_ssh = orchestrator.provision_sandbox("192.168.1.100", target_port=22)
    assert sb_ssh.decoy_type == "cowrie"
    assert sb_ssh.status == "DEPLOYED"
    assert "10.0.9." in sb_ssh.decoy_ip
    assert "192.168.1.100" in sb_ssh.diversion_rule
    
    # SMB port 445 -> Dionaea
    sb_smb = orchestrator.provision_sandbox("192.168.1.101", target_port=445)
    assert sb_smb.decoy_type == "dionaea"
    assert sb_smb.status == "DEPLOYED"
    assert sb_smb.decoy_ip != sb_ssh.decoy_ip

    # HTTP port 80 -> ElasticWeb
    sb_web = orchestrator.provision_sandbox("192.168.1.102", target_port=80)
    assert sb_web.decoy_type == "elasticweb"

    # Modbus port 502 -> Conpot
    sb_ics = orchestrator.provision_sandbox("192.168.1.103", target_port=502)
    assert sb_ics.decoy_type == "conpot"


def test_attacker_interaction_and_ttp_extraction():
    buffer = EpisodicReplayBuffer(max_size_per_stage=50)
    orchestrator = EpistemicDeceptionOrchestrator(replay_buffer=buffer)
    
    sb = orchestrator.provision_sandbox("10.50.0.44", target_port=445)
    
    commands = [
        "whoami /all",
        "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "net user administrator /domain",
    ]
    payload = b"MZ\x90\x00\x03\x00\x00\x00test_malicious_payload_binary"
    
    result = orchestrator.ingest_attacker_interaction(
        sandbox_id=sb.sandbox_id,
        commands=commands,
        payload_data=payload,
    )
    
    assert result["status"] == "CAPTURED"
    assert result["attacker_ip"] == "10.50.0.44"
    assert result["payload_hash"] is not None
    assert len(result["payload_hash"]) == 64
    assert result["closed_loop_learning_active"] is True
    assert result["learned_stage_id"] == 6  # Credential Access (Stage 6)
    
    # Verify TTP attribution
    ttps = result["extracted_ttps"]
    assert any("T1033" in t for t in ttps)
    assert any("T1003" in t for t in ttps)
    assert any("T1021" in t for t in ttps)
    
    # Verify exemplar entered the replay buffer
    assert len(buffer) == 1
    batch = buffer.sample_batch(1)
    assert batch is not None
    xs, futures, stages_t, mals = batch
    assert xs.shape == (1, 5, 35)
    assert stages_t[0][0].item() == 6


def test_ransomware_impact_closed_loop():
    buffer = EpisodicReplayBuffer(max_size_per_stage=50)
    orchestrator = EpistemicDeceptionOrchestrator(replay_buffer=buffer)
    
    sb = orchestrator.provision_sandbox("10.50.0.99", target_port=22)
    
    commands = [
        "vssadmin.exe delete shadows /all /quiet",
        "encrypt files --all",
    ]
    result = orchestrator.ingest_attacker_interaction(
        sandbox_id=sb.sandbox_id,
        commands=commands,
    )
    assert result["learned_stage_id"] == 12  # Impact
    assert any("T1486" in t for t in result["extracted_ttps"])
    assert len(buffer) == 1


def test_invalid_sandbox_raises():
    orchestrator = EpistemicDeceptionOrchestrator()
    with pytest.raises(KeyError):
        orchestrator.ingest_attacker_interaction("non_existent_sandbox", ["ls -la"])
