import streamlit as st
import pandas as pd
from PIL import Image
from nids_engine import detect_intrusions

# Page configuration
st.set_page_config(page_title="NetGuardian NIDS", page_icon="🛡️", layout="wide")

# Load and display logo
logo_path = "assets/netguardian_logo.png"  # Make sure the logo is in this path
try:
    logo = Image.open(logo_path)
    st.image(logo, width=100)
except FileNotFoundError:
    st.warning("Logo not found. Make sure it exists in the 'assets' folder.")

# Title and developer credit
st.markdown("<h1 style='color:#0E76A8;'>🛡️ NetGuardian - Network Intrusion Detection System (NIDS)</h1>", unsafe_allow_html=True)
st.markdown("👨‍💻 <b>Developed by Lights Oche</b>", unsafe_allow_html=True)
st.write("Upload a PCAP file and detect suspicious network activities in real time.")

# Upload section
st.subheader("📁 Upload a PCAP file")
uploaded_file = st.file_uploader("Choose a .pcap file", type=["pcap"], help="Upload a packet capture file (max 200MB)")

if uploaded_file is not None:
    st.success(f"✅ Uploaded {uploaded_file.name}")
    
    # Process and analyze the PCAP file
    with st.spinner("Analyzing network traffic..."):
        alerts, summary = detect_intrusions(uploaded_file)

    # Display Threat Summary
    if summary:
        st.subheader("⚠️ Threats Detected:")
        st.dataframe(pd.DataFrame(summary), use_container_width=True)
    
    # Display individual alerts
    if alerts:
        st.subheader("📊 Detailed Alert Logs:")
        st.code("\n".join(alerts), language="text")
    else:
        st.success("🎉 No threats detected in the uploaded PCAP!")

# Footer
st.markdown("---")
st.markdown("<center><small>🔧 Built with ❤️ by <b>Lights Oche</b> for the 3MTT July Knowledge Showcase</small></center>", unsafe_allow_html=True)
