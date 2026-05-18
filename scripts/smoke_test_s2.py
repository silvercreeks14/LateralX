import sys
sys.path.insert(0, '.')

from backend.ingest.parser import detect_and_parse
import os

files = [
    'sample_data/11_Ransomware_BlackVault/dc_auth_events.jsonl',
    'sample_data/11_Ransomware_BlackVault/endpoint_sysmon.csv',
    'sample_data/11_Ransomware_BlackVault/server_security_events.csv',
    'sample_data/11_Ransomware_BlackVault/perimeter_firewall.csv',
]

all_events = []
for fname in files:
    content = open(fname, encoding='utf-8').read()
    evs = detect_and_parse(fname, content)
    print(f"{os.path.basename(fname)}: {len(evs)} events")
    all_events.extend(evs)

print(f"\nTotal: {len(all_events)} events")
print(f"Users: {sorted(e.user for e in all_events if e.user and not e.user.endswith('$'))[:10]}")
print(f"Hosts: {sorted(set(e.source_host for e in all_events))[:8]}")

from backend.analysis.behavioral import analyze_behavior
result = analyze_behavior(all_events)
print(f"\nBehavioral anomalies: {len(result['anomalies'])}")
for a in result['anomalies']:
    print(f"  [{a['severity'].upper():6}] {a['anomaly_type']:40} entity={a['entity']}")

from backend.analysis.ml_anomaly import score_all_entities
scores = score_all_entities(all_events)
print(f"\nML anomaly scores (confidence={scores[0].confidence if scores else 'N/A'}):")
for s in scores[:6]:
    print(f"  {s.entity:20} score={s.anomaly_score:.3f} risk={s.risk_level:12} factors={s.contributing_factors[:2]}")
