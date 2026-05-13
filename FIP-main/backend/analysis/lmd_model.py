import pandas as pd
from pyvis.network import Network
import joblib
from sklearn.preprocessing import LabelEncoder
from pathlib import Path
from backend.schema import ForensicEvent

PROJECT_ROOT = Path(__file__).resolve().parents[2]

def run_lmd_model_and_graph(events: list[ForensicEvent], output_path: str | None = None) -> tuple[list[str], dict]:
    """
    Runs the trained Random Forest LMD model on the uploaded ForensicEvents.
    Generates the PyVis attack_graph.html and returns a list of anomalous event strings for the UI.
    """
    if not events:
        return []
        
    print("Extracting features from events...")
    # Convert ForensicEvents to DataFrame for the model
    data = []
    for e in events:
        # Extract fields, handling missing extra data
        extra = e.extra or {}
        dest_ip = extra.get('destinationip') or extra.get('DestinationIp') or ''
        src_ip = extra.get('sourceip') or extra.get('SourceIp') or e.source_host
        
        cmd = e.description
        if 'commandline' in extra:
             cmd = extra['commandline']
        elif 'CommandLine' in extra:
             cmd = extra['CommandLine']
             
        image = extra.get('image') or extra.get('Image') or ''
        proto = extra.get('protocol') or extra.get('Protocol') or 'Unknown'
        dport = extra.get('destinationport') or extra.get('DestinationPort') or 0
        
        data.append({
            'SourceIp': src_ip,
            'DestinationIp': dest_ip,
            'CommandLine': str(cmd),
            'Image': str(image),
            'Protocol': str(proto),
            'DestinationPort': dport,
            'EventID': e.event_id or 0
        })
        
    df_graph = pd.DataFrame(data)
    
    # Feature Engineering
    df_graph['DestinationPort'] = pd.to_numeric(df_graph['DestinationPort'], errors='coerce').fillna(0)
    df_graph['EventID'] = pd.to_numeric(df_graph['EventID'], errors='coerce').fillna(0)
    
    df_graph['Has_Kerberoast'] = df_graph['CommandLine'].str.contains('kerberoast|rubeus|ticket', case=False).astype(int)
    df_graph['Has_PTH'] = df_graph['CommandLine'].str.contains('sekurlsa::pth|mimikatz|pass-the-hash', case=False).astype(int)
    df_graph['Has_Log4Shell'] = df_graph['CommandLine'].str.contains('jndi:ldap|log4j', case=False).astype(int)
    df_graph['Has_Zerologon'] = df_graph['CommandLine'].str.contains('zerologon', case=False).astype(int)
    
    le_image = LabelEncoder()
    df_graph['Image_Encoded'] = le_image.fit_transform(df_graph['Image'])
    le_proto = LabelEncoder()
    df_graph['Protocol_Encoded'] = le_proto.fit_transform(df_graph['Protocol'])
    
    features = ['EventID', 'DestinationPort', 'Image_Encoded', 'Protocol_Encoded',
                'Has_Kerberoast', 'Has_PTH', 'Has_Log4Shell', 'Has_Zerologon']
    
    X = df_graph[features]
    
    model_path = PROJECT_ROOT / 'rf_model.pkl'
    if not model_path.exists():
        return ["Error: rf_model.pkl not found. Cannot run LMD classification."], {"nodes": [], "edges": []}
        
    clf = joblib.load(model_path)
    predictions = clf.predict(X)
    
    print("Building PyVis Graph...")
    net = Network(height='750px', width='100%', bgcolor='#222222', font_color='white', directed=True)
    
    nodes_info = {}
    edges_info = []
    anomalies_detected = []
    
    for i, row in df_graph.iterrows():
        src = str(row['SourceIp'])
        dst = str(row['DestinationIp'])
        
        pred = predictions[i]
        is_malicious = (pred != 0)
        
        attack_name = "Normal"
        if is_malicious:
            if row['Has_Kerberoast'] == 1: attack_name = "Kerberoasting"
            elif row['Has_PTH'] == 1: attack_name = "Pass-the-Hash"
            elif row['Has_Log4Shell'] == 1: attack_name = "Log4Shell"
            elif row['Has_Zerologon'] == 1: attack_name = "Zerologon"
            else:
                attack_name = "Zerologon/Log4Shell" if pred == 1 else "Kerberoasting/PTH"
                
            anomalies_detected.append(f"DETECTED LMD ATTACK [{attack_name}]: {src} -> {dst} via {row['Image']}")
                
        # Skip rows without IPs for the graph
        if src == 'nan' or dst == 'nan' or src == dst or not src or not dst:
            continue
            
        # Node logic
        if src not in nodes_info:
            nodes_info[src] = {'role': 'Normal'}
        if dst not in nodes_info:
            nodes_info[dst] = {'role': 'Normal'}
            
        if is_malicious:
            nodes_info[src]['role'] = 'Attacker'
            if nodes_info[dst]['role'] != 'Attacker':
                nodes_info[dst]['role'] = 'Victim'
                
        color = 'red' if is_malicious else 'green'
        
        title = f"Source {'(Attacker)' if is_malicious else ''}: {src}\n"
        title += f"Destination {'(Victim)' if is_malicious else ''}: {dst}\n"
        title += f"Classification: {attack_name}\n"
        title += f"Port: {row['DestinationPort']}\n"
        title += f"Protocol: {row['Protocol']}\n"
        title += f"EventID: {row['EventID']}\n"
        title += f"Image: {row['Image']}\n"
        
        cmd = str(row['CommandLine'])
        if len(cmd) > 100: cmd = cmd[:97] + '...'
        title += f"CommandLine: {cmd}"
        
        edges_info.append({
            'src': src, 'dst': dst, 'color': color, 
            'title': title, 'label': attack_name if is_malicious else ""
        })

    graph_data = {"nodes": [], "edges": []}
    
    for ip, data in nodes_info.items():
        role = data['role']
        if role == 'Attacker':
            net.add_node(ip, label=f"ATTACKER: {ip}", color='darkred', shape='triangle', title='Attacker Machine')
            graph_data['nodes'].append({"data": {"id": ip, "label": f"ATTACKER: {ip}", "color": "darkred", "shape": "triangle", "title": "Role: Attacker\nIP: " + ip}})
        elif role == 'Victim':
            net.add_node(ip, label=f"VICTIM: {ip}", color='orange', shape='box', title='Victim Machine')
            graph_data['nodes'].append({"data": {"id": ip, "label": f"VICTIM: {ip}", "color": "orange", "shape": "rectangle", "title": "Role: Victim\nIP: " + ip}})
        else:
            net.add_node(ip, label=ip, color='lightblue', shape='dot', title='Normal Machine')
            graph_data['nodes'].append({"data": {"id": ip, "label": ip, "color": "lightblue", "shape": "ellipse", "title": "Role: Normal\nIP: " + ip}})

    # Aggregate edges to reduce visual noise
    aggregated_edges = {}
    for edge in edges_info:
        key = (edge['src'], edge['dst'], edge['label'])
        if key not in aggregated_edges:
            aggregated_edges[key] = {**edge, 'count': 1}
        else:
            aggregated_edges[key]['count'] += 1

    for edge in aggregated_edges.values():
        attack_name = edge['label']
        count = edge['count']
        if attack_name and attack_name != 'Normal Traffic':
            # Distinct colors for the 4 attack types
            attack_colors = {
                "Zerologon": "#e11d48",       # Rose
                "Log4Shell": "#f59e0b",       # Amber
                "Kerberoasting": "#8b5cf6",   # Violet
                "Pass-the-Hash": "#10b981",   # Emerald
            }
            color = attack_colors.get(attack_name, 'red')
            label = f"{attack_name} ({count})" if count > 1 else attack_name
        else:
            color = 'gray'
            label = f"Normal ({count})" if count > 1 else 'Normal'

        net.add_edge(edge['src'], edge['dst'], color=color, title=edge['title'], label=label)
        graph_data['edges'].append({
            "data": {
                "id": f"{edge['src']}-{edge['dst']}-{attack_name}",
                "source": edge['src'],
                "target": edge['dst'],
                "label": label,
                "color": color,
                "title": edge['title']
            }
        })

    # Configure physics so it doesn't bounce endlessly like a ball
    net.repulsion(
        node_distance=300,
        central_gravity=0.1,
        spring_length=250,
        spring_strength=0.01,
        damping=0.95
    )

    # Save the legacy HTML graph
    graph_output_path = Path(output_path) if output_path else PROJECT_ROOT / 'attack_graph.html'
    net.save_graph(str(graph_output_path))
    
    # Deduplicate anomalies
    unique_anomalies = list(set(anomalies_detected))
    return unique_anomalies, graph_data
