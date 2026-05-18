import sys
sys.path.insert(0, '.')

from backend.ingest.parser import detect_and_parse
from backend.analysis.behavioral import analyze_behavior
from backend.analysis.storyline import build_storyline
from backend.analysis import rules as rules_mod
from backend.schema import IOC

SCENARIOS = {
    'PhishNet': [
        'sample_data/12_Phishing_PhishNet/endpoint_events.csv',
        'sample_data/12_Phishing_PhishNet/firewall_events.csv',
    ],
    'WebDoor': [
        'sample_data/13_WebShell_WebDoor/web_server_events.csv',
        'sample_data/13_WebShell_WebDoor/firewall_events.csv',
    ],
}

for scenario, files in SCENARIOS.items():
    evs = []
    for f in files:
        batch = detect_and_parse(f, open(f, encoding='utf-8').read())
        print(f"  {f.split('/')[-1]}: {len(batch)} events")
        evs += batch

    print(f"\n=== {scenario} ({len(evs)} events) ===")

    beh = analyze_behavior(evs)
    print(f"Behavioral anomalies: {len(beh['anomalies'])}")
    for a in beh['anomalies']:
        print(f"  [{a['severity'].upper():6}] {a['anomaly_type']:35} entity={a['entity']}")

    story = build_storyline(evs)
    ev = story['entry_vector'].replace('→', '->')
    print(f"\nEntry vector:   {ev}")
    print(f"Tactic chain:   {' > '.join(story['tactic_progression'])}")
    print(f"Lateral paths:  {len(story['lateral_paths'])}")
    for lp in story['lateral_paths']:
        print(f"  {lp['from_host']} -> {lp['to_host']} via {lp['method']}")
    print(f"Attack steps:   {len(story['attack_steps'])}")
    print(f"Compromised hosts: {story['blast_radius']['compromised_hosts']}")
    print(f"Compromised users: {story['blast_radius']['compromised_users']}")

    behav_sigma = rules_mod.generate_behavioral_sigma_rules(evs)
    test_iocs = [
        IOC(type='ip', value='185.199.110.55', context='C2 PhishNet', source='test', severity='high'),
        IOC(type='ip', value='91.234.55.12',   context='C2 WebDoor',  source='test', severity='high'),
    ]
    fw = rules_mod.generate_firewall_rules(test_iocs)
    print(f"\nBehavioral Sigma rules generated: {len(behav_sigma)}")
    for r in behav_sigma:
        print(f"  [{r['level'].upper():6}] {r['title']}")
    print(f"Firewall block lines: {len([r for r in fw if r.strip()])}")
    print()
