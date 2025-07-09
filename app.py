import streamlit as st
import pandas as pd
from nids_engine import detect_intrusions
import os

st.set_page_config(page_title="NetGuardian NIDS", layout="wide")
st.title("🛡️ NetGuardian - Network Intrusion Detection System (NIDS)")
st.markdown("Upload a PCAP file and detect suspicious network activities in real time.")

# Upload section
uploaded_file = st.file_uploader("📁 Upload a PCAP file", type=["pcap"])
if uploaded_file is not None:
    file_path = os.path.join("data", uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())

    st.success(f"✅ Uploaded {uploaded_file.name}")

    with st.spinner("Analyzing network traffic..."):
        try:
            df = detect_intrusions(file_path)

            if df.empty:
                st.success("✅ No threats detected.")
            else:
                st.warning("⚠️ Threats Detected:")
                st.dataframe(df)

                # Stats
                st.subheader("📊 Threat Summary")
                summary = df['threat'].value_counts().reset_index()
                summary.columns = ['Threat Type', 'Count']
                st.bar_chart(summary.set_index('Threat Type'))

                # Export report
                st.download_button(
                    label="📥 Download Report as CSV",
                    data=df.to_csv(index=False),
                    file_name="nids_alerts_report.csv",
                    mime="text/csv"
                )
        except Exception as e:
            st.error(f"❌ Error analyzing file: {e}")
else:
    st.info("Please upload a .pcap file to begin.")
