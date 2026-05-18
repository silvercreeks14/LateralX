from pathlib import Path

import joblib
import pandas as pd
from pyvis.network import Network
from sklearn.preprocessing import LabelEncoder

from backend.schema import ForensicEvent


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "rf_model.pkl"
DEFAULT_GRAPH_PATH = PROJECT_ROOT / "attack_graph.html"


def run_lmd_model_and_graph(
    events: list[ForensicEvent],
    output_path: str | Path | None = None,
) -> tuple[list[str], dict]:
    """
    Run the trained LMD Random Forest model and generate graph data plus HTML.
    """
    if not events:
        return [], {"nodes": [], "edges": []}

    data = []
    for event in events:
        extra = event.extra or {}
        cmd = extra.get("CommandLine") or extra.get("commandline") or event.description or ""
        data.append({
            "SourceIp": extra.get("SourceIp") or extra.get("sourceip") or event.source_host or "",
            "DestinationIp": extra.get("DestinationIp") or extra.get("destinationip") or "",
            "CommandLine": str(cmd),
            "Image": str(extra.get("Image") or extra.get("image") or ""),
            "Protocol": str(extra.get("Protocol") or extra.get("protocol") or "Unknown"),
            "DestinationPort": extra.get("DestinationPort") or extra.get("destinationport") or 0,
            "EventID": event.event_id or 0,
        })

    df_graph = pd.DataFrame(data)
    df_graph["DestinationPort"] = pd.to_numeric(df_graph["DestinationPort"], errors="coerce").fillna(0)
    df_graph["EventID"] = pd.to_numeric(df_graph["EventID"], errors="coerce").fillna(0)
    df_graph["Has_Kerberoast"] = df_graph["CommandLine"].str.contains(
        "kerberoast|rubeus|ticket", case=False, regex=True
    ).astype(int)
    df_graph["Has_PTH"] = df_graph["CommandLine"].str.contains(
        "sekurlsa::pth|mimikatz|pass-the-hash", case=False, regex=True
    ).astype(int)
    df_graph["Has_Log4Shell"] = df_graph["CommandLine"].str.contains(
        "jndi:ldap|log4j", case=False, regex=True
    ).astype(int)
    df_graph["Has_Zerologon"] = df_graph["CommandLine"].str.contains(
        "zerologon", case=False, regex=True
    ).astype(int)

    df_graph["Image_Encoded"] = LabelEncoder().fit_transform(df_graph["Image"])
    df_graph["Protocol_Encoded"] = LabelEncoder().fit_transform(df_graph["Protocol"])

    features = [
        "EventID",
        "DestinationPort",
        "Image_Encoded",
        "Protocol_Encoded",
        "Has_Kerberoast",
        "Has_PTH",
        "Has_Log4Shell",
        "Has_Zerologon",
    ]

    if not MODEL_PATH.exists():
        return [f"Error: {MODEL_PATH.name} not found. Cannot run LMD classification."], {"nodes": [], "edges": []}

    classifier = joblib.load(MODEL_PATH)
    predictions = classifier.predict(df_graph[features])

    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    nodes_info: dict[str, dict[str, str]] = {}
    edges_info: list[dict] = []
    anomalies: list[str] = []

    for i, row in df_graph.iterrows():
        src = str(row["SourceIp"]).strip()
        dst = str(row["DestinationIp"]).strip()
        pred = predictions[i]
        is_malicious = pred != 0

        attack_name = "Normal"
        if is_malicious:
            if row["Has_Kerberoast"] == 1:
                attack_name = "Kerberoasting"
            elif row["Has_PTH"] == 1:
                attack_name = "Pass-the-Hash"
            elif row["Has_Log4Shell"] == 1:
                attack_name = "Log4Shell"
            elif row["Has_Zerologon"] == 1:
                attack_name = "Zerologon"
            else:
                attack_name = "Zerologon/Log4Shell" if pred == 1 else "Kerberoasting/PTH"
            anomalies.append(f"DETECTED LMD ATTACK [{attack_name}]: {src} -> {dst} via {row['Image']}")

        if src.lower() == "nan" or dst.lower() == "nan" or src == dst or not src or not dst:
            continue

        nodes_info.setdefault(src, {"role": "Normal"})
        nodes_info.setdefault(dst, {"role": "Normal"})
        if is_malicious:
            nodes_info[src]["role"] = "Attacker"
            if nodes_info[dst]["role"] != "Attacker":
                nodes_info[dst]["role"] = "Victim"

        title = (
            f"Source: {src}\n"
            f"Destination: {dst}\n"
            f"Classification: {attack_name}\n"
            f"Port: {row['DestinationPort']}\n"
            f"Protocol: {row['Protocol']}\n"
            f"EventID: {row['EventID']}\n"
            f"Image: {row['Image']}\n"
            f"CommandLine: {str(row['CommandLine'])[:100]}"
        )
        edges_info.append({
            "src": src,
            "dst": dst,
            "title": title,
            "label": attack_name if is_malicious else "",
        })

    graph_data = {"nodes": [], "edges": []}
    for ip, data in nodes_info.items():
        role = data["role"]
        if role == "Attacker":
            net.add_node(ip, label=f"ATTACKER: {ip}", color="darkred", shape="triangle", title="Attacker Machine")
            label, color, shape = f"ATTACKER: {ip}", "darkred", "triangle"
        elif role == "Victim":
            net.add_node(ip, label=f"VICTIM: {ip}", color="orange", shape="box", title="Victim Machine")
            label, color, shape = f"VICTIM: {ip}", "orange", "rectangle"
        else:
            net.add_node(ip, label=ip, color="lightblue", shape="dot", title="Normal Machine")
            label, color, shape = ip, "lightblue", "ellipse"
        graph_data["nodes"].append({
            "data": {"id": ip, "label": label, "role": role, "color": color, "shape": shape}
        })

    aggregated_edges: dict[tuple[str, str, str], dict] = {}
    for edge in edges_info:
        key = (edge["src"], edge["dst"], edge["label"])
        if key not in aggregated_edges:
            aggregated_edges[key] = {**edge, "count": 1}
        else:
            aggregated_edges[key]["count"] += 1

    attack_colors = {
        "Zerologon": "#e11d48",
        "Log4Shell": "#f59e0b",
        "Kerberoasting": "#8b5cf6",
        "Pass-the-Hash": "#10b981",
    }
    for edge in aggregated_edges.values():
        attack_name = edge["label"]
        count = edge["count"]
        color = attack_colors.get(attack_name, "red") if attack_name else "gray"
        label = f"{attack_name} ({count})" if attack_name and count > 1 else attack_name
        if not label:
            label = f"Normal ({count})" if count > 1 else "Normal"

        net.add_edge(edge["src"], edge["dst"], color=color, title=edge["title"], label=label)
        graph_data["edges"].append({
            "data": {
                "id": f"{edge['src']}-{edge['dst']}-{attack_name or 'normal'}",
                "source": edge["src"],
                "target": edge["dst"],
                "label": label,
                "color": color,
                "title": edge["title"],
                "count": count,
                "suspicious": bool(attack_name),
            }
        })

    net.repulsion(
        node_distance=300,
        central_gravity=0.1,
        spring_length=250,
        spring_strength=0.01,
        damping=0.95,
    )
    graph_output_path = Path(output_path) if output_path else DEFAULT_GRAPH_PATH
    net.save_graph(str(graph_output_path))

    return sorted(set(anomalies)), graph_data
