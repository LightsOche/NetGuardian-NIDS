from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

# ============================
# Intrusion Detection Settings
# ============================

BLACKLISTED_IPS = {
    "192.168.1.100",
    "10.0.0.5"
}

SUSPICIOUS_PORTS = {
    6667,     # IRC
    31337,    # Back Orifice / malware
    12345     # NetBus
}

PORT_SCAN_THRESHOLD = 10  # Unique ports per IP before flagging port scan

# ============================
# Intrusion Detection Function
# ============================

def detect_intrusions(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return [], {"Error": f"Could not read PCAP file: {str(e)}"}

    alerts = []
    scan_tracker = {}

    for pkt in packets:
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # 🚨 Blacklisted IP Detection
                if src_ip in BLACKLISTED_IPS or dst_ip in BLACKLISTED_IPS:
                    alerts.append(f"⚠️ Blacklisted IP detected: {src_ip} <--> {dst_ip}")

                # 🔍 Suspicious Port Access Detection
                if TCP in pkt or UDP in pkt:
                    layer4 = pkt[TCP] if TCP in pkt else pkt[UDP]
                    if hasattr(layer4, 'dport') and layer4.dport in SUSPICIOUS_PORTS:
                        alerts.append(f"⚠️ Suspicious port {layer4.dport} accessed by {src_ip}")

                # 📊 Track ports for port scan detection
                if src_ip not in scan_tracker:
                    scan_tracker[src_ip] = set()

                if TCP in pkt and hasattr(pkt[TCP], 'dport'):
                    scan_tracker[src_ip].add(pkt[TCP].dport)
                elif UDP in pkt and hasattr(pkt[UDP], 'dport'):
                    scan_tracker[src_ip].add(pkt[UDP].dport)

        except Exception:
            # Skip malformed packets
            continue

    # 🔎 Port Scan Detection
    for ip, ports in scan_tracker.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            alerts.append(f"⚠️ Port scan detected from {ip} - attempted {len(ports)} ports")

    summary = {
        "Total Packets": len(packets),
        "Alerts": len(alerts),
        "Unique Sources": len(scan_tracker),
    }

    return alerts, summary
