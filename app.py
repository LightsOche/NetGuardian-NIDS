import streamlit as st
import pandas as pd
from nids_engine import detect_intrusions
from PIL import Image
import io
import tempfile

# Page configuration
st.set_page_config(page_title="NetGuardian NIDS", page_icon="🛡️", layout="wide")

# Load and display logo
st.markdown("<h1 style='text-align: center;'>🛡️ NetGuardian - Network Intrusion Detection System (NIDS)</h1>", unsafe_allow_html=True)
st.markdown("<h5 style='text-align: center;'>👨‍💻 Developed by <strong>Lights Oche</strong> for the 3MTT July Knowledge Showcase</h5>", unsafe_allow_html=True)

logo_path = "assets/netguardian_logo.png"
try:
    logo = Image.open(logo_path)
    st.image(logo, width=180)
except Exception as e:
    st.warning(f"⚠️ Logo could not be loaded: {e}")

# File uploader
st.markdown("### 📁 Upload a PCAP file")
uploaded_file = st.file_uploader("Choose a .pcap file", type="pcap", help="Upload a network capture file (max 200MB)")

if uploaded_file is not None:
    st.success(f"✅ Uploaded {uploaded_file.name}")
    
    try:
        # Write uploaded file to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        # Run intrusion detection
        alerts, summary = detect_intrusions(tmp_path)

        # Display alerts
        st.markdown("## ⚠️ Threats Detected:")
        if not alerts.empty:
            st.dataframe(alerts, use_container_width=True)
        else:
            st.info("✅ No threats detected in this PCAP file.")

        # Display summary
        st.markdown("## 📊 Threat Summary")
        st.dataframe(pd.DataFrame.from_dict(summary, orient="index", columns=["Count"]), use_container_width=True)

    except Exception as e:
        st.error(f"❌ An error occurred while processing the PCAP file:\n\n{e}")
        st.stop()

# Footer
st.markdown("---")
st.markdown("<p style='text-align: center;'>🔧 Built with ❤️ by Lights Oche | <a href='https://github.com/LightsOche/NetGuardian-NIDS' target='_blank'>View Source on GitHub</a></p>", unsafe_allow_html=True)
