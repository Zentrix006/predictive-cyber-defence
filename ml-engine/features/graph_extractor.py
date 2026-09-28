"""Dynamic Network Graph Snapshot Extractor.

Converts flow records / PCAP observations into attributed multigraph tensors
(node features, edge connectivity, edge flow attributes) for the Graph-Temporal World Model.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import torch


@dataclass
class NetworkGraphSnapshot:
    nodes: torch.Tensor             # [1, N, D_v]
    edge_index: torch.Tensor        # [1, 2, E]
    edges: torch.Tensor             # [1, E, D_e]
    node_to_idx: Dict[str, int]
    idx_to_node: Dict[int, str]
    num_nodes: int
    num_edges: int


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP belongs to private/internal networks (RFC 1918 / loopback / link-local)."""
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_str.split(":")[0])
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return any(ip_str.startswith(p) for p in (
            "10.", "192.168.", "172.", "127.", "SERVER-", "HOST-", "GATEWAY", "FIREWALL", "DC-"
        ))


def canonicalize_node(
    ip_str: str,
    known_nodes: Optional[Dict[str, int]] = None,
    current_external_count: int = 0,
    max_external_nodes: int = 32,
) -> str:
    """
    Canonicalize node identifier with Subnet Supernode Pooling to prevent
    graph state explosion under spoofed external IP floods.
    """
    if is_internal_ip(ip_str):
        return ip_str
    if known_nodes is not None and ip_str in known_nodes:
        return ip_str
    if current_external_count >= max_external_nodes:
        return "EXT_SPOOFED_CLUSTER"
    return ip_str


def build_graph_from_flow_records(
    flows: List[Dict[str, Any]],
    node_dim: int = 16,
    edge_dim: int = 35,
    max_external_nodes: int = 32,
) -> NetworkGraphSnapshot:
    """
    Construct a NetworkGraphSnapshot tensor tuple from a list of observed flow dicts.
    Applies Subnet Supernode Pooling to prevent Graph OOM and state explosion under
    randomized source-IP volumetric floods.
    """
    node_to_idx: Dict[str, int] = {}
    edges_src: List[int] = []
    edges_dst: List[int] = []
    edge_features_list: List[np.ndarray] = []
    external_count = 0

    # Map nodes with supernode pooling protection
    for flow in flows:
        raw_src = str(flow.get("src_ip", "10.0.0.1"))
        raw_dst = str(flow.get("dst_ip", "10.0.0.2"))

        src = canonicalize_node(raw_src, node_to_idx, external_count, max_external_nodes)
        if src == raw_src and not is_internal_ip(raw_src) and src not in node_to_idx:
            external_count += 1

        dst = canonicalize_node(raw_dst, node_to_idx, external_count, max_external_nodes)
        if dst == raw_dst and not is_internal_ip(raw_dst) and dst not in node_to_idx:
            external_count += 1

        if src not in node_to_idx:
            node_to_idx[src] = len(node_to_idx)
        if dst not in node_to_idx:
            node_to_idx[dst] = len(node_to_idx)

        edges_src.append(node_to_idx[src])
        edges_dst.append(node_to_idx[dst])

        # Extract edge features
        feat = flow.get("features")
        if feat is not None and len(feat) == edge_dim:
            edge_features_list.append(np.asarray(feat, dtype=np.float32))
        else:
            # Fallback heuristic feature vector from standard fields
            ef = np.zeros(edge_dim, dtype=np.float32)
            ef[0] = float(flow.get("forward_packets", 1))
            ef[1] = float(flow.get("reverse_packets", 1))
            ef[2] = float(flow.get("forward_bytes", 100))
            ef[3] = float(flow.get("reverse_bytes", 100))
            ef[4] = float(flow.get("duration_seconds", 1.0))
            ef[5] = float(flow.get("port", 80)) / 65535.0
            edge_features_list.append(ef)

    num_nodes = len(node_to_idx)
    num_edges = len(edges_src)

    # Build node attribute matrix
    node_matrix = np.zeros((num_nodes, node_dim), dtype=np.float32)
    # Compute node degrees & activity volume
    for s, d in zip(edges_src, edges_dst):
        node_matrix[s, 0] += 1.0  # out-degree
        node_matrix[d, 1] += 1.0  # in-degree

    # Identify server-like nodes (high in-degree)
    for i in range(num_nodes):
        if node_matrix[i, 1] > 2.0:
            node_matrix[i, 2] = 1.0  # probable service/server
        node_matrix[i, 3] = float(i) / max(num_nodes, 1)  # relative position

    idx_to_node = {idx: ip for ip, idx in node_to_idx.items()}

    # Format tensors with batch dimension B=1
    nodes_t = torch.from_numpy(node_matrix).unsqueeze(0)  # [1, N, D_v]
    if num_edges > 0:
        edge_idx_t = torch.tensor([edges_src, edges_dst], dtype=torch.long).unsqueeze(0)  # [1, 2, E]
        edges_t = torch.from_numpy(np.array(edge_features_list, dtype=np.float32)).unsqueeze(0)  # [1, E, D_e]
    else:
        edge_idx_t = torch.zeros(1, 2, 0, dtype=torch.long)
        edges_t = torch.zeros(1, 0, edge_dim, dtype=torch.float32)

    return NetworkGraphSnapshot(
        nodes=nodes_t,
        edge_index=edge_idx_t,
        edges=edges_t,
        node_to_idx=node_to_idx,
        idx_to_node=idx_to_node,
        num_nodes=num_nodes,
        num_edges=num_edges,
    )
