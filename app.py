import streamlit as st
from nids_engine import detect_intrusions
import pandas as pd
import os

# Set Streamlit page configuration
st.set_page_config(page_title="NetGuardian NIDS", page_icon="🛡️")

# App Title and Developer Name
st.title("🛡️ NetGuardian - Network Intrusion Detection System (NIDS)")
st.markdown("### 👨‍💻 Developed by **Lights Oche**")
st.markdown("Upload a PCAP file and detect suspicious network activities in real time.")

# Upload section
st.markdown("#### 📁 Upload a PCAP file")
uploaded_file = st.file_uploader("Choose a .pcap file", type=["pcap"], help="Maximum file size: 200MB")

# Process uploaded file
if uploaded_file is not None:
    # Save file to temp path
    file_path = os.path.join("data", uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success(f"✅ Uploaded {uploaded_file.name}")

    # Analyze the file
    st.markdown("#### ⚠️ Threats Detected:")
    alerts = detect_intrusions(file_path)

    if alerts:
        df = pd.DataFrame(alerts)
        st.dataframe(df)
        
        st.markdown("#### 📊 Threat Summary")
        summary = df['Threat Type'].value_counts().reset_index()
        summary.columns = ['Threat Type', 'Count']
        st.bar_chart(summary.set_index('Threat Type'))
    else:
        st.success("✅ No threats detected in the uploaded PCAP file.")

# Footer
st.markdown("---")
st.markdown(
    "<center>🔧 Built with ❤️ by <b>Lights Oche</b> for the <b>3MTT July Knowledge Showcase</b></center>",
    unsafe_allow_html=True
)
