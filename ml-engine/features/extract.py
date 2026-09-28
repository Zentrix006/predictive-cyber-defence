"""
Feature extraction for SIH26153 World Model.

Combines flow-level (NetFlow/IPFIX-style) and packet-level attributes
from CSV telemetry (UNSW-NB15, CIC-IDS, NSL-KDD) and PCAP (Scapy).
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from .mitre_map import attack_label_to_mitre, ATTACK_CAT_TO_MITRE


# Flow + packet feature columns used for state vectors (UNSW-NB15 aligned)
FLOW_FEATURE_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "sload", "dload", "ct_srv_src", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
]

PACKET_FEATURE_COLS = [
    "sttl", "dttl", "swin", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len",
]

CATEGORICAL_COLS = ["proto", "service", "state"]


@dataclass
class FeatureMatrix:
    """Timestamped, normalised feature matrix for world-model training/inference."""
    features: np.ndarray          # [N, F]
    feature_names: List[str]
    labels: Optional[np.ndarray]  # binary infiltration label
    stages: Optional[np.ndarray]  # MITRE stage indices
    attack_cats: Optional[List[str]]
    timestamps: Optional[np.ndarray]
    # Provenance for uploads whose source is not a tabular telemetry dataset.
    # Kept out of the model tensor, but surfaced to callers for auditability.
    source_meta: Optional[Dict[str, Any]] = None

    @property
    def num_features(self) -> int:
        return self.features.shape[1]


def _encode_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in CATEGORICAL_COLS:
        if col in out.columns:
            out[col] = pd.Categorical(out[col].fillna("-").astype(str)).codes.astype(np.float32)
        else:
            out[col] = 0.0
    return out


def load_unsw_csv(path: Union[str, Path], max_rows: Optional[int] = None) -> pd.DataFrame:
    """Load UNSW-NB15 train/test CSV (handles BOM)."""
    df = pd.read_csv(path, encoding="utf-8-sig", nrows=max_rows)
    df.columns = [c.strip() for c in df.columns]
    return df


def load_nsl_kdd_csv(path: Union[str, Path], max_rows: Optional[int] = None) -> pd.DataFrame:
    """
    Load NSL-KDD (no header). Maps to a subset of flow/packet-like features
    and MITRE stages via attack name.
    """
    # Classic 41 features + label (+ optional difficulty)
    cols = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
        "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack", "difficulty",
    ]
    df = pd.read_csv(path, header=None, names=cols[:43], nrows=max_rows)
    if df.shape[1] == 42:
        df.columns = cols[:42]
    # Map to UNSW-like schema for shared pipeline
    mapped = pd.DataFrame({
        "dur": df["duration"],
        "proto": df["protocol_type"],
        "service": df["service"],
        "state": df["flag"],
        "spkts": df["count"],
        "dpkts": df["srv_count"],
        "sbytes": df["src_bytes"],
        "dbytes": df["dst_bytes"],
        "rate": df["serror_rate"],
        "sttl": df["wrong_fragment"],
        "dttl": df["urgent"],
        "sload": df["same_srv_rate"],
        "dload": df["diff_srv_rate"],
        "sloss": df["rerror_rate"],
        "dloss": df["srv_rerror_rate"],
        "sinpkt": df["dst_host_count"],
        "dinpkt": df["dst_host_srv_count"],
        "sjit": df["dst_host_same_srv_rate"],
        "djit": df["dst_host_diff_srv_rate"],
        "swin": df["dst_host_serror_rate"],
        "dwin": df["dst_host_srv_serror_rate"],
        "tcprtt": df["dst_host_rerror_rate"],
        "synack": df["dst_host_srv_rerror_rate"],
        "ackdat": df["srv_serror_rate"],
        "smean": df["src_bytes"].clip(upper=1500),
        "dmean": df["dst_bytes"].clip(upper=1500),
        "trans_depth": df["hot"],
        "response_body_len": df["num_compromised"],
        "ct_srv_src": df["srv_count"],
        "ct_dst_ltm": df["dst_host_count"],
        "ct_src_dport_ltm": df["dst_host_same_src_port_rate"],
        "ct_dst_sport_ltm": df["dst_host_srv_diff_host_rate"],
        "ct_dst_src_ltm": df["count"],
        "ct_src_ltm": df["srv_diff_host_rate"],
        "ct_srv_dst": df["dst_host_srv_count"],
        "attack_cat": df["attack"].astype(str),
        "label": (df["attack"].astype(str).str.lower() != "normal").astype(int),
    })
    return mapped


# Mapping CICFlowMeter (CIC-IDS2017 / CTU-13) columns → UNSW-like schema
_CFM_TO_SCHEMA = {
    "flow duration": "dur",
    "total fwd packets": "spkts",
    "tot fwd pkts": "spkts",
    "total backward packets": "dpkts",
    "tot bwd pkts": "dpkts",
    "total length of fwd packets": "sbytes",
    "totlen fwd pkts": "sbytes",
    "total length of bwd packets": "dbytes",
    "totlen bwd pkts": "dbytes",
    "flow bytes/s": "rate",
    "flow packets/s": "rate",
    "flow iat mean": "sinpkt",
    "flow iat std": "dinpkt",
    "flow iat max": "sjit",
    "flow iat min": "djit",
    "fwd header length": "swin",
    "bwd header length": "dwin",
    "fwd segments avg bytes": "smean",
    "avg fwd segment size": "smean",
    "bwd segments avg bytes": "dmean",
    "avg bwd segment size": "dmean",
    "avg packet size": "trans_depth",
    "average packet size": "trans_depth",
    "packet length mean": "dttl",
    "packet length std": "dttl",
    "syn flag count": "synack",
    "ack flag count": "ackdat",
    "root segment forward": "smean",
    "down/up ratio": "sload",
    "fwd packets/s": "sload",
    "bwd packets/s": "dload",
    "fwd packet length mean": "smean",
    "fwd packet length std": "smean",
    "bwd packet length mean": "dmean",
    "bwd packet length std": "dmean",
    "fwd iat mean": "sinpkt",
    "bwd iat mean": "dinpkt",
    "fwd iat total": "sjit",
    "bwd iat total": "djit",
    "packet length variance": "dttl",
}


def detect_cicflowmeter(df: pd.DataFrame) -> bool:
    """True if the CSV is CICFlowMeter-style (CIC-IDS / CTU-13)."""
    norm = {c.strip().lower() for c in df.columns}
    flow_sig = norm & {
        "total fwd packets", "tot fwd pkts", "total backward packets", "tot bwd pkts",
        "flow duration", "flow byts/s", "flow iat mean", "total length of fwd packets",
        "totlen fwd pkts",
    }
    has_label = bool(norm & {"label"})
    return bool(flow_sig) and has_label


def _strip_label_col(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Return (frame WITHOUT label col, label series) after normalising names."""
    out = df.copy()
    out.columns = [str(c).strip() for c in out.columns]
    label_col = None
    for c in out.columns:
        if c.strip().lower() == "label":
            label_col = c
            break
    labels = None
    if label_col is not None:
        labels = out[label_col]
        out = out.drop(columns=[label_col])
    return out, labels


def load_cicflowmeter_csv(path: Union[str, Path], max_rows: Optional[int] = None) -> pd.DataFrame:
    """
    Load CICFlowMeter-style CSV (CIC-IDS2017 labelled flows or CTU-13).
    Maps to the UNSW-like schema for the shared feature pipeline.
    """
    df = pd.read_csv(path, nrows=max_rows)
    df, raw_labels = _strip_label_col(df)
    norm = {str(c).strip().lower(): str(c).strip() for c in df.columns}

    mapped = {}
    for cfm_col, schema_col in _CFM_TO_SCHEMA.items():
        if cfm_col in norm and schema_col not in mapped:
            mapped[schema_col] = df[norm[cfm_col]]

    for col in ("dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
                "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
                "swin", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
                "trans_depth", "response_body_len", "ct_srv_src", "ct_dst_ltm",
                "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm",
                "ct_srv_dst"):
        mapped.setdefault(col, 0.0)

    out = pd.DataFrame(mapped)

    out["proto"] = "tcp"
    if "destination port" in norm:
        out["service"] = df[norm["destination port"]].astype(str)
    else:
        out["service"] = "-"
    out["state"] = "CON"

    if raw_labels is not None:
        lab = pd.to_numeric(raw_labels, errors="coerce")
        if lab.notna().all():
            # Keep the raw label token (e.g. CTU-13 "1"/"0", KDD "0.0"/"1.0")
            # so attack_label_to_mitre can resolve it to a real MITRE stage
            # instead of collapsing every attack into a generic "Attack".
            raw = raw_labels.astype(str).str.strip()
            out["attack_cat"] = raw
            out["label"] = (lab.fillna(0) != 0).astype(int)
        else:
            raw = raw_labels.astype(str).str.strip()
            out["attack_cat"] = raw.astype(str)
            out["label"] = (raw.str.lower() != "benign").astype(int)
    else:
        out["attack_cat"] = "Normal"
        out["label"] = 0

    return out


def load_kdd99_csv(path: Union[str, Path], max_rows: Optional[int] = None) -> pd.DataFrame:
    """
    Load KDD Cup 1999 (DARPA-era, no header), 41 features + label.
    Reuses the NSL-KDD column schema since both share the classic 41-feature layout.
    """
    return load_nsl_kdd_csv(path, max_rows=max_rows)


def dataframe_to_feature_matrix(df: pd.DataFrame) -> FeatureMatrix:
    """Convert a flow/packet dataframe into a normalised FeatureMatrix."""
    df = _encode_categoricals(df)
    names = FLOW_FEATURE_COLS + PACKET_FEATURE_COLS + CATEGORICAL_COLS
    for col in names:
        if col not in df.columns:
            df[col] = 0.0
    X = df[names].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=np.float32)

    # Robust scaling (median / IQR) — offline, no leakage across files at train time
    median = np.median(X, axis=0)
    q75 = np.percentile(X, 75, axis=0)
    q25 = np.percentile(X, 25, axis=0)
    iqr = np.where((q75 - q25) < 1e-6, 1.0, q75 - q25)
    X = ((X - median) / iqr).astype(np.float32)
    X = np.clip(X, -10, 10)

    labels = None
    if "label" in df.columns:
        labels = pd.to_numeric(df["label"], errors="coerce").fillna(0).to_numpy(dtype=np.int64)

    attack_cats: List[str] = []
    stages = None
    if "attack_cat" in df.columns:
        attack_cats = [str(x).strip() for x in df["attack_cat"].tolist()]
        stages = np.array([attack_label_to_mitre(c) for c in attack_cats], dtype=np.int64)
    elif labels is not None:
        stages = np.where(labels == 0, 13, 1).astype(np.int64)  # unknown vs initial_access
        attack_cats = ["Normal" if l == 0 else "Attack" for l in labels]

    timestamps = np.arange(len(X), dtype=np.float32)
    return FeatureMatrix(
        features=X,
        feature_names=names,
        labels=labels,
        stages=stages,
        attack_cats=attack_cats,
        timestamps=timestamps,
    )


def extract_from_csv_bytes(data: bytes, filename: str = "upload.csv") -> FeatureMatrix:
    """Ingest uploaded CSV (UNSW-like or NSL-KDD)."""
    name = filename.lower()
    bio = io.BytesIO(data)
    if "cic" in name or "ctu" in name:
        return dataframe_to_feature_matrix(load_cicflowmeter_csv(bio, max_rows=None))
    if "nsl" in name or "kdd" in name or "kdd99" in name or "kddcup" in name:
        # peek headerless
        df = load_nsl_kdd_csv(bio, max_rows=None)
        return dataframe_to_feature_matrix(df)
    else:
        try:
            df = pd.read_csv(bio, encoding="utf-8-sig")
            df.columns = [c.strip() for c in df.columns]
            if "attack" in df.columns and "attack_cat" not in df.columns and "dur" not in df.columns:
                bio.seek(0)
                df = load_nsl_kdd_csv(bio, max_rows=None)
            elif detect_cicflowmeter(df):
                bio.seek(0)
                df = load_cicflowmeter_csv(bio, max_rows=None)
            elif "attack_cat" not in df.columns and "label" not in df.columns:
                # Best-effort: treat as unlabeled flows
                if "Label" in df.columns:
                    df["label"] = (df["Label"].astype(str).str.upper() != "BENIGN").astype(int)
                    df["attack_cat"] = df["Label"].astype(str)
        except Exception:
            bio.seek(0)
            df = load_nsl_kdd_csv(bio, max_rows=None)
    return dataframe_to_feature_matrix(df)


def _pcap_http(pkt) -> Optional[Dict[str, Any]]:
    """Best-effort HTTP request metadata from a scapy packet (manual TCP parse)."""
    try:
        import re
        from scapy.all import Raw, TCP  # type: ignore

        if TCP not in pkt or Raw not in pkt:
            return None
        payload = bytes(pkt[Raw].load)
        m = re.match(br"^(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) (\S+) HTTP/", payload)
        if not m:
            return None
        method = m.group(1).decode("latin1", "ignore")
        path = m.group(2).decode("latin1", "ignore")
        hm = re.search(br"(?i)host:\s*([^\r\n]+)", payload)
        host = hm.group(1).decode("latin1", "ignore").strip() if hm else ""
        return {"http_method": method, "host": host, "path": path, "is_response": False}
    except Exception:
        pass
    return None


def shannon_entropy(data: Union[str, bytes]) -> float:
    """Calculate Shannon entropy (bits/symbol) of text or byte sequence."""
    if not data:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _pcap_dns_names(pkt) -> List[str]:
    """DNS query names in a packet (recurse through all queries)."""
    names = []
    try:
        from scapy.all import DNS, DNSQR  # type: ignore

        if DNS in pkt and pkt[DNS].qr == 0:
            for i in range(pkt[DNS].qdcount):
                qr = pkt[DNS].qd[i]
                if isinstance(qr, DNSQR) and qr.qname:
                    names.append(qr.qname.decode("latin1", "ignore").rstrip(".").lower())
    except Exception:
        pass
    return names


def _pcap_tls_sni(pkt) -> Optional[str]:
    """TLS client hello SNI server name (scapy raw parse)."""
    try:
        from scapy.all import Raw  # type: ignore

        if "TCP" not in pkt:
            return None
        sport = int(pkt["TCP"].sport)
        if sport != 443:
            return None
        if Raw not in pkt:
            return None
        payload = bytes(pkt[Raw].load)
        if len(payload) < 11 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        i = 6 + 2 + 32  # skip handshake + version + random(32)
        if i + 2 > len(payload):
            return None
        sess_len = int.from_bytes(payload[i:i + 2], "big")
        i += 2 + sess_len
        if i + 2 > len(payload):
            return None
        ciph_len = int.from_bytes(payload[i:i + 2], "big")
        i += 2 + ciph_len
        if i + 1 > len(payload):
            return None
        comp_len = int(payload[i])
        i += 1 + comp_len
        if i + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[i:i + 2], "big")
        i += 2
        end = i + ext_len
        while i + 4 <= end:
            etype = int.from_bytes(payload[i:i + 2], "big")
            elen = int.from_bytes(payload[i + 2:i + 4], "big")
            i += 4
            edata = payload[i:i + elen]
            i += elen
            if etype == 0 and len(edata) >= 3:
                name_len = int.from_bytes(edata[2:4], "big")
                if name_len > 0 and 4 + name_len <= len(edata):
                    return edata[4:4 + name_len].decode("latin1", "ignore").lower()
    except Exception:
        pass
    return None


def extract_from_pcap_bytes(data: bytes) -> Tuple[FeatureMatrix, List[Dict[str, Any]]]:
    """
    Packet-level + aggregated flow features from a PCAP using Scapy.
    Builds session-like rows from 5-tuples and returns protocol-aware
    per-flow metadata (HTTP, DNS, TLS, indicators) alongside the matrix.
    """
    from collections import defaultdict
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, rdpcap  # type: ignore

    packets = rdpcap(io.BytesIO(data))
    packet_counts = {"total": len(packets), "ipv4": 0, "ipv6": 0, "non_ip": 0}
    sessions: Dict[Tuple, List] = defaultdict(list)
    applied_sni: Dict[Tuple, str] = {}
    flow_http: Dict[Tuple, Dict[str, Any]] = {}
    flow_dns: Dict[Tuple, set] = {}

    for pkt in packets:
        if IP in pkt:
            ip = pkt[IP]
            packet_counts["ipv4"] += 1
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            packet_counts["ipv6"] += 1
        else:
            packet_counts["non_ip"] += 1
            continue
        proto = "tcp" if TCP in pkt else ("udp" if UDP in pkt else ("icmp" if ICMP in pkt else "other"))
        sport = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else 0)
        dport = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else 0)
        key = (ip.src, ip.dst, sport, dport, proto)
        sessions[key].append(pkt)

        http = _pcap_http(pkt)
        if http:
            flow_http.setdefault(key, http)

        dns_names = _pcap_dns_names(pkt)
        if dns_names:
            flow_dns.setdefault(key, set()).update(dns_names)

        sni = _pcap_tls_sni(pkt)
        if sni:
            applied_sni.setdefault(key, sni)

    rows = []
    flow_meta = []
    port_to_srv = {
        53: "dns", 80: "http", 443: "https", 8080: "http-alt",
        21: "ftp", 22: "ssh", 25: "smtp", 445: "smb", 3389: "rdp",
        88: "kerberos", 135: "msrpc", 5985: "winrm-http", 5986: "winrm-https",
    }

    for (src, dst, sport, dport, proto), pkts in sessions.items():
        if not pkts:
            continue
        times = [float(p.time) for p in pkts]
        sizes = [len(p) for p in pkts]
        ttls = [
            int(p[IP].ttl) if IP in p else int(p[IPv6].hlim)
            for p in pkts if IP in p or IPv6 in p
        ]
        wins = [int(p[TCP].window) for p in pkts if TCP in p]
        syn = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x02)
        ack = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x10)
        rst = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x04)
        fin = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x01)
        iats = np.diff(sorted(times)) if len(times) > 1 else np.array([0.0])
        dur = max(times) - min(times) if len(times) > 1 else 0.0
        sbytes = float(sum(sizes))

        # Protocol-aware annotation
        http = flow_http.get((src, dst, sport, dport, proto), {})
        h_method = http.get("http_method", "")
        h_host = http.get("host", "")
        h_path = http.get("path", "")
        sni = applied_sni.get((src, dst, sport, dport, proto), "")
        qnames = sorted(flow_dns.get((src, dst, sport, dport, proto), set()))
        service = port_to_srv.get(dport, str(dport))
        ext_host = (h_host or sni or dst)

        indicators = []
        h_path_l = h_path.lower()
        is_exe_path = any(h_path_l.endswith(s) for s in (".exe", ".dll", ".bat", ".ps1", ".scr", ".bin", ".vbs"))
        # C2 beacon / exfil: HTTP POST to a raw-IP host (no hostname)
        if h_method and h_host and h_host.replace(".", "").isdigit() and h_method.upper() == "POST":
            indicators.append(f"HTTP POST to raw-IP host {h_host}{(' ' + h_path) if h_path else ''} (C2 / exfil)"
                              + (", repeated beacon" if len(pkts) >= 20 else ""))
        # Executable/download over raw-IP HTTP (malware delivery / evasion)
        if h_method and h_host and h_host.replace(".", "").isdigit() and is_exe_path:
            indicators.append(f"Executable delivered over raw-IP HTTP: {h_host}{h_path}")
        # DNS resolving an executable/library name (Lokibot evasion trick)
        for q in qnames:
            if q.startswith(".") and any(q.endswith(s) for s in (".exe", ".dll", ".bat", ".ps1", ".scr", ".bin")):
                indicators.append(f"DNS query resolves executable name '{q}'")
        if qnames and any(q.startswith(".") for q in qnames):
            indicators.append(f"dot-prefixed DNS queries ({len([q for q in qnames if q.startswith('.')])} names)")

        # DNS covert tunnel / exfiltration via lexical Shannon entropy of subdomain labels
        if qnames:
            subdomain_labels = [part for q in qnames for part in q.split(".")[:-2] if len(part) > 2]
            max_label_entropy = max((shannon_entropy(part) for part in subdomain_labels), default=0.0)
            max_label_len = max((len(part) for part in subdomain_labels), default=0)
            if (max_label_entropy >= 3.5 and max_label_len >= 20) or max_label_len >= 28:
                indicators.append(
                    f"DNS covert tunnel / exfiltration (Label entropy={max_label_entropy:.2f}, max_len={max_label_len}, queries={len(qnames)})"
                )

        # Low-and-slow HTTP holding pattern (Slowloris attack vector)
        if proto == "tcp" and dport in (80, 443, 8080) and dur >= 8.0 and sbytes < 800 and len(pkts) >= 4:
            holding_ratio = dur / max(sbytes, 1.0)
            if holding_ratio >= 0.02:
                indicators.append(
                    f"Low-and-slow HTTP holding pattern (Slowloris: dur={dur:.1f}s, bytes={int(sbytes)}, holding_ratio={holding_ratio:.2f})"
                )

        # Advanced Lateral Movement & Living-off-the-Land (Pass-the-Hash, Kerberoasting, WinRM)
        if dport in (445, 135, 3389, 88, 5985, 5986):
            if proto == "tcp" and (syn > 0 or len(pkts) >= 3):
                indicators.append(
                    f"Lateral movement vector targeting internal admin service {service}:{dport} (pkts={len(pkts)})"
                )

        # Asymmetric covert ICMP channel
        if proto == "icmp" and sbytes > 200:
            indicators.append(f"ICMP covert data channel (bytes={int(sbytes)})")

        row = {
            "dur": dur,
            "proto": proto,
            "service": service,
            "state": "CON" if ack else ("INT" if syn else "OTH"),
            "spkts": float(len(pkts)),
            "dpkts": float(ack),
            "sbytes": sbytes,
            "dbytes": 0.0,
            "rate": float(len(pkts) / dur) if dur > 0 else float(len(pkts)),
            "sttl": float(np.mean(ttls)) if ttls else 0.0,
            "dttl": float(np.std(ttls)) if len(ttls) > 1 else 0.0,
            "sload": sbytes / dur if dur > 0 else sbytes,
            "dload": 0.0,
            "sloss": float(rst),
            "dloss": float(fin),
            "sinpkt": float(np.mean(iats)) if len(iats) else 0.0,
            "dinpkt": float(np.var(iats)) if len(iats) else 0.0,
            "sjit": float(np.max(iats)) if len(iats) else 0.0,
            "djit": float(np.min(iats)) if len(iats) else 0.0,
            "swin": float(np.mean(wins)) if wins else 0.0,
            "dwin": float(np.std(wins)) if len(wins) > 1 else 0.0,
            "tcprtt": 0.0,
            "synack": float(syn),
            "ackdat": float(ack),
            "smean": float(np.mean(sizes)),
            "dmean": float(np.std(sizes)) if len(sizes) > 1 else 0.0,
            "trans_depth": float(sum(1 for h in flow_http.values() if h.get("http_method"))),
            "response_body_len": 0.0,
            "ct_srv_src": float(len(pkts)),
            "ct_dst_ltm": float(dport),
            "ct_src_dport_ltm": float(sport),
            "ct_dst_sport_ltm": float(syn + ack),
            "ct_dst_src_ltm": float(len(pkts)),
            "ct_src_ltm": float(len(pkts)),
            "ct_srv_dst": float(dport % 100),
            "attack_cat": "Malicious" if indicators else "Normal",
            "label": 1 if indicators else 0,
        }
        rows.append(row)
        flow_meta.append({
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "service": service,
            "packets": len(pkts),
            "http_method": h_method,
            "host": h_host,
            "path": h_path,
            "sni": sni,
            "dns_queries": qnames[:5],
            "indicators": indicators,
            "risk": "high" if indicators else "low",
        })

    if not rows:
        raise ValueError(
            "No usable IPv4 or IPv6 flows were found in this capture "
            f"({packet_counts['total']} packets: {packet_counts['ipv4']} IPv4, "
            f"{packet_counts['ipv6']} IPv6, {packet_counts['non_ip']} non-IP)."
        )

    matrix = dataframe_to_feature_matrix(pd.DataFrame(rows))
    matrix.source_meta = {
        "format": "pcap",
        "packets_total": packet_counts["total"],
        "ip_packets": packet_counts["ipv4"] + packet_counts["ipv6"],
        "ipv4_packets": packet_counts["ipv4"],
        "ipv6_packets": packet_counts["ipv6"],
        "non_ip_packets": packet_counts["non_ip"],
        "extracted_flows": len(flow_meta),
    }
    return matrix, flow_meta


def build_state_sequences(
    matrix: FeatureMatrix,
    context_window: int = 10,
    horizon: int = 4,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Build sliding windows for dynamics learning:
    X_ctx: [N, context, F]  — observed history S_{t-c:t}
    Y_next: [N, F]          — next state S_{t+1} (dynamics target)
    y_stage: [N, horizon]   — future MITRE stages
    y_infil: [N, horizon]   — future infiltration labels
    """
    X = matrix.features
    stages = matrix.stages if matrix.stages is not None else np.zeros(len(X), dtype=np.int64)
    labels = matrix.labels if matrix.labels is not None else np.zeros(len(X), dtype=np.int64)

    total = context_window + horizon
    xs, yn, ys, yi = [], [], [], []
    for t in range(len(X) - total + 1):
        ctx = X[t:t + context_window]
        nxt = X[t + context_window]  # S_{t+1}
        fut_stages = stages[t + context_window:t + total]
        fut_labels = labels[t + context_window:t + total]
        xs.append(ctx)
        yn.append(nxt)
        ys.append(fut_stages)
        yi.append(fut_labels)
    return (
        np.asarray(xs, dtype=np.float32),
        np.asarray(yn, dtype=np.float32),
        np.asarray(ys, dtype=np.int64),
        np.asarray(yi, dtype=np.int64),
    )
