"""
Map dataset attack labels → MITRE ATT&CK stage indices.

Indices align with StageClassifier.STAGES in models/heads.py.
"""
from __future__ import annotations

from typing import Dict

# Must match ml-engine/models/heads.py StageClassifier.STAGES
MITRE_STAGES = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
    "unknown",
]

STAGE_TO_IDX: Dict[str, int] = {s: i for i, s in enumerate(MITRE_STAGES)}

# UNSW-NB15 attack_cat → MITRE
ATTACK_CAT_TO_MITRE: Dict[str, str] = {
    "Normal": "unknown",
    "normal": "unknown",
    "Generic": "impact",
    "Exploits": "execution",
    "Fuzzers": "reconnaissance",
    "DoS": "impact",
    "Reconnaissance": "reconnaissance",
    "Analysis": "discovery",
    "Backdoor": "persistence",
    "Shellcode": "execution",
    "Worms": "lateral_movement",
}

# NSL-KDD / CIC-style labels → MITRE
LABEL_TO_MITRE: Dict[str, str] = {
    "normal": "unknown",
    "benign": "unknown",
    "probe": "reconnaissance",
    "ipsweep": "reconnaissance",
    "nmap": "reconnaissance",
    "portsweep": "reconnaissance",
    "satan": "reconnaissance",
    "dos": "impact",
    "neptune": "impact",
    "smurf": "impact",
    "pod": "impact",
    "teardrop": "impact",
    "back": "impact",
    "land": "impact",
    "apache2": "impact",
    "udpstorm": "impact",
    "processtable": "impact",
    "mailbomb": "impact",
    "r2l": "initial_access",
    "guess_passwd": "credential_access",
    "ftp_write": "initial_access",
    "imap": "initial_access",
    "phf": "execution",
    "multihop": "lateral_movement",
    "warezmaster": "exfiltration",
    "warezclient": "exfiltration",
    "spy": "collection",
    "u2r": "privilege_escalation",
    "buffer_overflow": "privilege_escalation",
    "loadmodule": "privilege_escalation",
    "perl": "execution",
    "rootkit": "persistence",
    "sqlattack": "execution",
    "xss": "initial_access",
    "bruteforce": "credential_access",
    "bot": "command_and_control",
    "ddos": "impact",
    "portscan": "reconnaissance",
    "infiltration": "lateral_movement",
    "heartbleed": "credential_access",
    "web attack": "initial_access",
    # CIC-IDS2017 attack labels
    "portscan": "reconnaissance",
    "ddos": "impact",
    "infiltration": "lateral_movement",
    "bots": "command_and_control",
    "benign": "unknown",
    "web attack brute force": "initial_access",
    "web attack xss": "initial_access",
    "web attack sql injection": "initial_access",
    "bot": "command_and_control",
    "brute force": "credential_access",
    # CTU-13 (numeric labels)
    "1": "command_and_control",
    "0": "unknown",
    # KDD99 numeric/edge labels
    "smurf": "impact",
    "neptune": "impact",
    "satan": "reconnaissance",
    "ipsweep": "reconnaissance",
    "portsweep": "reconnaissance",
    "nmap": "reconnaissance",
    "warezclient": "exfiltration",
    "warezmaster": "exfiltration",
    "teardrop": "impact",
    "pod": "impact",
    "back": "impact",
    "guess_passwd": "credential_access",
    "buffer_overflow": "privilege_escalation",
    "land": "impact",
    "imap": "initial_access",
    "rootkit": "persistence",
    "loadmodule": "privilege_escalation",
    "ftp_write": "initial_access",
    "multihop": "lateral_movement",
    "phf": "execution",
    "perl": "execution",
    "spy": "collection",
    "xterm": "execution",
    "httptunnel": "command_and_control",
    "named": "privilege_escalation",
    "sendmail": "privilege_escalation",
    "xlock": "initial_access",
    "xsnoop": "initial_access",
    "snmpgetattack": "impact",
    "snmpguess": "credential_access",
    "ps": "collection",
    "sqlattack": "execution",
    "apache2": "impact",
    "processtable": "impact",
    "udpstorm": "impact",
    "mailbomb": "impact",
    "worm": "lateral_movement",
    "mscan": "reconnaissance",
    "saint": "reconnaissance",
    "normal": "unknown",
}


def attack_label_to_mitre(label: str) -> int:
    """Return MITRE stage index for a free-form attack label / category."""
    if label is None:
        return STAGE_TO_IDX["unknown"]
    raw = str(label).strip()
    if raw in ATTACK_CAT_TO_MITRE:
        return STAGE_TO_IDX[ATTACK_CAT_TO_MITRE[raw]]
    key = raw.lower().replace("-", "").replace(" ", "").replace("_", "").strip(".")
    # KDD99 "0.00" glitch or numeric NaN-like → unknown
    if key in ("0", "000", "0.00", "nan", ""):
        return STAGE_TO_IDX["unknown"]
    # Direct stage name?
    for stage in MITRE_STAGES:
        if key == stage.replace("_", ""):
            return STAGE_TO_IDX[stage]
    # Fuzzy NSL/CIC/KDD
    for k, stage in LABEL_TO_MITRE.items():
        kk = k.replace("_", "").replace("-", "").replace(" ", "")
        if kk in key or key in kk:
            return STAGE_TO_IDX[stage]
    if raw.lower() in ("0", "normal", "benign", "-"):
        return STAGE_TO_IDX["unknown"]
    return STAGE_TO_IDX["unknown"]
