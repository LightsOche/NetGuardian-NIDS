import streamlit as st
from nids_engine import detect_intrusions
import altair as alt
import pandas as pd
from datetime import datetime
import base64
import os

# Branding
st.set_page_config(page_title="NetGuardian NIDS", page_icon="🛡️", layout="wide")

st.image("assets/netguardian_logo.png", width=200)
st.title("🛡️ NetGuardian - Network Intrusion Detection System (NIDS)")
st.markdown("👨‍💻 Developed by **Lights Oche** for the **3MTT July Knowledge Showcase**")
st.write("Upload a `.pcap` file to analyze and detect suspicious network activity.")

# Upload
uploaded_file = st.file_uploader("📁 Upload a PCAP file", type=["pcap"])

# Helper for downloadable report
def generate_download_link(text, filename):
    b64 = base64.b64encode(text.encode()).decode()
    href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">📄 Download Threat Report</a>'
    return href

# Main Processing
if uploaded_file:
    try:
        alerts, summary = detect_intrusions(uploaded_file)

        if alerts:
            st.subheader("⚠️ Threats Detected:")
            severity_labels = []

            # Add severity classification
            for alert in alerts:
                if "Blacklisted" in alert or "Brute" in alert or "Payload" in alert:
                    severity = "🔥 High"
                elif "Suspicious port" in alert or "HTTP" in alert:
                    severity = "⚠️ Medium"
                else:
                    severity = "ℹ️ Low"
                severity_labels.append({"Alert": alert, "Severity": severity, "Time": datetime.now().strftime("%H:%M:%S")})
                st.markdown(f"- {alert} [{severity}]")

            # Convert to DataFrame for chart
            df = pd.DataFrame(severity_labels)

            # Downloadable Report
            report_text = "\n".join([f"{row['Time']} - {row['Alert']} ({row['Severity']})" for _, row in df.iterrows()])
            st.markdown(generate_download_link(report_text, "netguardian_threat_report.txt"), unsafe_allow_html=True)

            # Timeline Chart
            st.subheader("📊 Threat Timeline")
            chart = alt.Chart(df).mark_circle(size=120).encode(
                x="Time:T",
                y="Severity:N",
                tooltip=["Alert", "Severity", "Time"]
            ).properties(height=300)
            st.altair_chart(chart, use_container_width=True)

            # Summary Counts
            st.subheader("📌 Threat Summary")
            for k, v in summary.items():
                st.write(f"- **{k}**: {v}")

        else:
            st.success("✅ No threats detected in this PCAP file.")

    except Exception as e:
        st.error(f"❌ An error occurred while processing the PCAP file:\n\n{e}")
else:
    st.info("Please upload a `.pcap` file to begin.")
