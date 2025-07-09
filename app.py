import streamlit as st
import pandas as pd
from nids_engine import detect_intrusions

st.set_page_config(
    page_title="NetGuardian - NIDS",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Network-icon.svg/2048px-Network-icon.svg.png", width=100)
    st.title("🛡️ NetGuardian")
    st.markdown("**Developer:** Lights Oche")
    st.markdown("**Project:** 3MTT July Knowledge Showcase")
    st.markdown("📧 lightsoche@gmail.com")
    st.markdown("[🌐 GitHub](https://github.com/LightsOche/NetGuardian-NIDS)")

# Main Interface
st.title("🛡️ NetGuardian - Network Intrusion Detection System (NIDS)")
st.markdown("👨‍💻 Developed by **Lights Oche**")
st.markdown("Upload a `.pcap` file to scan for network threats in real time using a simple and intuitive dashboard.")

uploaded_file = st.file_uploader("📁 Upload a PCAP file", type="pcap")

if uploaded_file:
    st.success(f"✅ Uploaded {uploaded_file.name}")
    
    with st.spinner("Analyzing PCAP file for threats..."):
        alerts_df = detect_intrusions(uploaded_file)

    if not alerts_df.empty:
        st.warning("⚠️ **Threats Detected!**")
        st.dataframe(alerts_df, use_container_width=True)

        # Allow report download
        csv = alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Threat Report (CSV)",
            data=csv,
            file_name="threat_report.csv",
            mime="text/csv"
        )
    else:
        st.success("✅ No threats detected in the PCAP file.")

else:
    st.info("Please upload a `.pcap` file to begin.")

st.markdown("---")
st.caption("🔧 Built with ❤️ by **Lights Oche** for the 3MTT July Knowledge Showcase")
