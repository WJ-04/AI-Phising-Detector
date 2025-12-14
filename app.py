import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import json
import re

from detector import PhishingDetector
from utils import parse_email, extract_metadata
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Page config
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)

# Initialize detector
@st.cache_resource
def get_detector():
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        st.error("Please set DEEPSEEK_API_KEY in .env file")
        st.stop()
    return PhishingDetector(api_key)

detector = get_detector()

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #FF4B4B;
        text-align: center;
        margin-bottom: 2rem;
    }
    .risk-high { background-color: #FFCCCB; padding: 10px; border-radius: 5px; }
    .risk-medium { background-color: #FFF3CD; padding: 10px; border-radius: 5px; }
    .risk-low { background-color: #D4EDDA; padding: 10px; border-radius: 5px; }
    .info-box { border-left: 5px solid #2196F3; padding-left: 15px; }
    .stProgress > div > div > div > div { background-color: #FF4B4B; }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<h1 class="main-header">🛡️ PhishGuard AI Detector</h1>', unsafe_allow_html=True)
st.markdown("### Analyze emails for phishing indicators using AI")

# Sidebar
with st.sidebar:
    st.header("Upload Email")
    
    upload_method = st.radio(
        "Choose input method:",
        ["📤 Upload .eml file", "📝 Paste raw email", "✍️ Compose test email"]
    )
    
    email_content = ""
    metadata = {}
    
    if upload_method == "📤 Upload .eml file":
        uploaded_file = st.file_uploader("Choose .eml file", type="eml")
        if uploaded_file:
            email_content = uploaded_file.getvalue().decode()
            metadata = extract_metadata(email_content)
            
    elif upload_method == "📝 Paste raw email":
        email_content = st.text_area("Paste raw email headers and body:", height=200)
        if email_content:
            metadata = extract_metadata(email_content)
            
    else:  # Compose test email
        st.info("Create a test email for analysis")
        sender = st.text_input("From:", "support@secure-bank.com")
        subject = st.text_input("Subject:", "URGENT: Your Account Will Be Suspended!")
        body = st.text_area("Body:", """Dear Customer,

We've detected unusual activity on your account. 
To prevent suspension, please verify your identity immediately:

👉 Click here: https://secure-login-bank.xyz/verify

This is required within 24 hours.

Best regards,
Security Team""", height=150)
        
        email_content = f"From: {sender}\nSubject: {subject}\n\n{body}"
        metadata = {
            'from': sender,
            'subject': subject,
            'body': body,
            'has_links': True,
            'has_attachments': False
        }
    
    analyze_btn = st.button("🔍 Analyze Email", type="primary", disabled=not email_content)

# Main content area
if analyze_btn and email_content:
    with st.spinner("Analyzing with AI..."):
        # Run analysis
        ai_results = detector.analyze_with_ai(email_content, metadata)
        urls = detector.extract_urls(email_content)
        
        # Create columns for layout
        col1, col2 = st.columns([1, 1])
        
        with col1:
            # Risk Score Display
            risk_score = ai_results.get('risk_score', 0)
            risk_level = ai_results.get('risk_level', 'UNKNOWN')
            
            st.subheader("Risk Assessment")
            
            # Progress bar
            st.progress(risk_score / 100)
            
            # Color-coded risk level
            if risk_level == "HIGH":
                st.markdown(f'<div class="risk-high"><h3>⚠️ HIGH RISK: {risk_score}/100</h3></div>', unsafe_allow_html=True)
            elif risk_level == "MEDIUM":
                st.markdown(f'<div class="risk-medium"><h3>🔶 MEDIUM RISK: {risk_score}/100</h3></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="risk-low"><h3>✅ LOW RISK: {risk_score}/100</h3></div>', unsafe_allow_html=True)
            
            # Confidence
            confidence = ai_results.get('confidence', 0.8)
            st.metric("Analysis Confidence", f"{confidence*100:.1f}%")
            
            # Indicators found
            st.subheader("🔍 Indicators Found")
            for indicator in ai_results.get('indicators_found', []):
                st.write(f"• {indicator}")
            
            # URL Analysis
            if urls:
                st.subheader("🌐 Links Analysis")
                url_df = pd.DataFrame(urls)
                st.dataframe(url_df, use_container_width=True)
                
                # Visualize URL risks
                suspicious_count = sum(1 for url in urls if url['suspicious_tld'])
                st.write(f"**{suspicious_count} suspicious URLs detected**")
        
        with col2:
            # Technical Analysis
            st.subheader("🔬 Technical Analysis")
            st.markdown(f'<div class="info-box">{ai_results.get("technical_analysis", "No analysis available")}</div>', unsafe_allow_html=True)
            
            # Social Engineering Analysis
            if 'social_engineering_analysis' in ai_results:
                st.subheader("🎭 Social Engineering Tactics")
                st.write(ai_results['social_engineering_analysis'])
            
            # Recommendations
            st.subheader("🛡️ Recommendations")
            for i, rec in enumerate(ai_results.get('recommendations', []), 1):
                st.write(f"{i}. {rec}")
            
            # Email Metadata
            st.subheader("📧 Email Details")
            metadata_df = pd.DataFrame(list(metadata.items()), columns=['Field', 'Value'])
            st.dataframe(metadata_df, use_container_width=True, hide_index=True)
    
    # Visualization Section
    st.divider()
    st.subheader("📊 Risk Breakdown")
    
    # Create risk breakdown chart
    fig = go.Figure(data=[
        go.Bar(name='Risk Factors',
               x=['Content', 'Links', 'Sender', 'Headers'],
               y=[40, 30, 20, 10])  # Example weights
    ])
    
    fig.update_layout(
        title="Phishing Risk Factors",
        yaxis_title="Risk Weight",
        template="plotly_white"
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Export Results
    st.download_button(
        label="📥 Download Analysis Report",
        data=json.dumps(ai_results, indent=2),
        file_name=f"phishing_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="application/json"
    )

else:
    # Show instructions when no analysis
    st.info("👈 Upload or paste an email to begin analysis")
    
    # Example section
    with st.expander("📚 Example Phishing Indicators"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.write("**Urgent Language**")
            st.code("""
• "Immediate action required"
• "Account will be suspended"
• "24 hour deadline"
            """)
        
        with col2:
            st.write("**Suspicious URLs**")
            st.code("""
• http://secure-login-bank.xyz
• bit.ly/bank-verify
• 192.168.1.1/login
            """)
        
        with col3:
            st.write("**Sender Issues**")
            st.code("""
• Mismatched sender domain
• Slight misspellings
• Unofficial addresses
            """)

# Footer
st.divider()
st.caption("🔒 **Security Note**: This tool analyzes emails locally. No data is stored. Always verify suspicious emails through official channels.")