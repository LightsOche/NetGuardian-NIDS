from scapy.all import *
import pandas as pd
from collections import Counter

# Example: Blacklisted IPs
BLACKLISTED_IPS = ['192.168.1.100', '10.0.0.66']

# Store alerts
alerts = []

def detect_intrusions(pcap_file):
    packets = rdpcap(pcap_file)
    src_ips = []
    dst_ports = []

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_ips.append(src_ip)

            # Check for TCP port scan
            if TCP in pkt:
                dst_port = pkt[TCP].dport
                dst_ports.append(dst_port)

                if src_ip in BLACKLISTED_IPS:
                    alerts.append({
                        'timestamp': pkt.time,
                        'source': src_ip,
                        'destination': dst_ip,
                        'threat': 'Blacklisted IP access'
                    })

                if dst_port in [22, 23, 3389]:
                    alerts.append({
                        'timestamp': pkt.time,
                        'source': src_ip,
                        'destination': dst_ip,
                        'threat': f'Suspicious port access: {dst_port}'
                    })

    # Detect Port Scan (same IP hitting many ports)
    scan_threshold = 10
    port_scan_ips = [ip for ip, count in Counter(src_ips).items() if count > scan_threshold]
    for ip in port_scan_ips:
        alerts.append({
            'timestamp': '',
            'source': ip,
            'destination': '',
            'threat': 'Potential Port Scan'
        })

    return pd.DataFrame(alerts)
