
## 🚀 Live Demo

Try the NetGuardian NIDS app here:  
👉 [Click to Launch App](https://netguardian-nids-vqvepvbcuja5og8dvaxd94.streamlit.app/)
# 🛡️ NetGuardian NIDS

**NetGuardian** is a simple Network Intrusion Detection System (NIDS) built with Python, Scapy, and Streamlit. It allows users to upload `.pcap` files and scans them for suspicious activity such as:

- Blacklisted IP addresses
- Port scanning
- Unusual port activity
- Protocol abuse

---

## 🚀 Features

- 📁 Upload and scan `.pcap` network traffic files
- ⚠️ Detect and display intrusion alerts
- 📊 Visual threat summary
- 📄 Export alerts to CSV

---

## 🧠 How It Works

1. **Upload** a PCAP file through the Streamlit dashboard
2. **nids_engine.py** uses Scapy to parse and analyze packets
3. Alerts are generated based on predefined rules and suspicious behavior
4. Alerts are shown in a user-friendly table and can be downloaded

---

## 🛠️ Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/YourUsername/NetGuardian-NIDS.git
cd NetGuardian-NIDS
pip install -r requirements.txt
