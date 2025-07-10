from scapy.all import rdpcap, TCP, UDP, ICMP, DNSQR, Raw
from collections import defaultdict

BLACKLISTED_IPS = {"192.168.1.10", "10.0.0.5"}
SUSPICIOUS_PORTS = {21, 23, 2323, 3389}
FTP_PORT = 21
SSH_PORT = 22
DNS_PORT = 53
HTTP_PORT = 80
HTTPS_PORT = 443
ICMP_THRESHOLD = 10

SUSPICIOUS_KEYWORDS = [b'cmd=', b'union select', b'<?php', b'powershell', b'wget', b'/bin/sh']

def detect_intrusions(pcap_file):
    packets = rdpcap(pcap_file)
    alerts = []
    summary = defaultdict(int)

    connection_attempts = defaultdict(int)
    login_failures = defaultdict(int)
    dns_queries = defaultdict(int)
    icmp_requests = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer("IP"):
            ip_layer = pkt["IP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Blacklisted IPs
            if src_ip in BLACKLISTED_IPS or dst_ip in BLACKLISTED_IPS:
                alerts.append(f"🚨 Blacklisted IP detected: {src_ip} → {dst_ip}")
                summary["Blacklisted IPs"] += 1

            # ICMP Scan Detection
            if pkt.haslayer(ICMP):
                icmp_requests[src_ip] += 1

            # TCP/UDP Scans and Checks
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                dport = pkt.dport if pkt.haslayer(TCP) else pkt[UDP].dport

                if dport in SUSPICIOUS_PORTS:
                    alerts.append(f"⚠️ Suspicious port activity: {src_ip} → {dst_ip} on port {dport}")
                    summary["Suspicious Ports"] += 1

                # Malformed TCP Header
                if pkt.haslayer(TCP):
                    flags = pkt[TCP].flags
                    if flags == 0:
                        alerts.append(f"🧪 Malformed TCP packet (null flags) from {src_ip}")
                        summary["Malformed TCP Packets"] += 1

                # Brute Force
                if pkt.haslayer(TCP):
                    sport = pkt[TCP].sport
                    if dport in [FTP_PORT, SSH_PORT] or sport in [FTP_PORT, SSH_PORT]:
                        connection_attempts[(src_ip, dport)] += 1
                        if pkt.haslayer(Raw) and b"530" in pkt[Raw].load:
                            login_failures[(src_ip, dport)] += 1

                # Suspicious Payloads
                if pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load.lower()
                    for keyword in SUSPICIOUS_KEYWORDS:
                        if keyword in raw_data:
                            alerts.append(f"💀 Suspicious payload from {src_ip}: contains '{keyword.decode(errors='ignore')}'")
                            summary["Suspicious Payloads"] += 1

                    # HTTP Anomalies
                    if dport == HTTP_PORT and (b'POST' in raw_data or b'GET' in raw_data):
                        if b'.php' in raw_data or b'/upload' in raw_data or b'eval(' in raw_data:
                            alerts.append(f"🌐 HTTP Anomaly: potential shell upload or script execution from {src_ip}")
                            summary["HTTP Anomalies"] += 1

            # DNS Tunneling
            if pkt.haslayer(UDP) and pkt[UDP].dport == DNS_PORT and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="ignore")
                dns_queries[qname] += 1
                if len(qname) > 50 or qname.count('.') > 5:
                    alerts.append(f"🐍 Possible DNS tunneling: {qname} from {src_ip}")
                    summary["DNS Tunneling"] += 1

    # Flag Brute Force Attempts
    for (ip, port), count in login_failures.items():
        if count > 5:
            alerts.append(f"🔐 Possible brute-force login attempts from {ip} on port {port} ({count} failures)")
            summary["Brute Force Attempts"] += 1

    # Flag ICMP Ping Scans
    for ip, count in icmp_requests.items():
        if count > ICMP_THRESHOLD:
            alerts.append(f"📡 ICMP scan detected from {ip} ({count} echo requests)")
            summary["ICMP Scanning"] += 1

    return alerts, dict(summary)
