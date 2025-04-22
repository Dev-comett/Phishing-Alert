import streamlit as st
import joblib
from feature_extractor import extract_features
import base64
import requests

# Load the model
model = joblib.load('model.pkl')

# Function to check VirusTotal API
def check_virustotal(url, api_key):
    # Encode the URL to base64 format (required by VirusTotal API)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {
        'x-apikey': api_key
    }
    base_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(base_url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        result = response.json()

        # Check if the 'data' key exists in the response
        if 'data' in result:
            analysis_stats = result['data'].get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = analysis_stats.get('malicious', 0)
            total_count = analysis_stats.get('total', 1)  # Avoid division by zero
            
            return malicious_count, total_count
        else:
            # Handle the case where 'data' key is missing
            st.warning("⚠️ URL not found in VirusTotal database.")
            return None, None
    except requests.exceptions.RequestException as e:
        st.error(f"Error while fetching from VirusTotal: {e}")
        return None, None

# Streamlit app content
st.set_page_config(page_title="Phish Alert 🔒", layout="centered")
st.title("🔎 Phish Alert")
st.caption("Check if a URL is **malicious** or **safe** using an ML model trained on phishing patterns.")

# Session state for history
if "history" not in st.session_state:
    st.session_state.history = []

# Get the API key from the secrets.toml file
api_key = st.secrets["virustotal_api_key"]

# URL input
url_input = st.text_input("🔗 Enter a URL to scan")

# Analyze button
if st.button("🔍 Analyze"):
    if url_input.strip() == "":
        st.warning("⚠️ Please enter a URL.")
    else:
        features = extract_features(url_input)
        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0][prediction]

        vt_malicious, vt_total = check_virustotal(url_input, api_key)

        # Save history and display results
        st.session_state.history.append((url_input, prediction, proba, vt_malicious, vt_total))

        # Show results
        if prediction == 1:
            st.error(f"🚨 Model Prediction: Malicious URL ({proba:.2%} confidence)")
        else:
            st.success(f"✅ Model Prediction: Safe URL ({proba:.2%} confidence)")

        if vt_malicious is not None and vt_total is not None:
            vt_confidence = vt_malicious / vt_total if vt_total > 0 else 0
            if vt_confidence > 0.5:
                st.error(f"🚨 VirusTotal Analysis: **Malicious** URL ({vt_confidence*100:.2f}% malicious)")
            else:
                st.success(f"✅ VirusTotal Analysis: **Safe** URL ({vt_confidence*100:.2f}% malicious)")
        else:
            st.warning("⚠️ Unable to fetch VirusTotal results.")

        st.progress(proba)

        with st.expander("🧠 Model Input Features Breakdown"):
            feature_names = [
                "URL Length",
                "Count of '@'",
                "Count of '-'",
                "Count of '.'",
                "Contains HTTPS",
                "Uses IP Address",
                "Path Length"
            ]
            for name, value in zip(feature_names, features):
                st.write(f"**{name}**: {value}")

# History log
if st.session_state.history:
    st.divider()
    st.subheader("📜 Scan History")
    for idx, (url, pred, prob, vt_malicious, vt_total) in enumerate(reversed(st.session_state.history), 1):
        label = "Malicious" if pred == 1 else "Safe"
        color = "red" if pred == 1 else "green"
        st.markdown(f"{idx}. `{url}` → :{color}[**{label}**] ({prob:.2%})")

# Reset history button
if st.button("🔁 Reset History"):
    st.session_state.history = []
    st.success("History cleared.")

# Footer: Inject custom styles and footer HTML directly into app.py
st.markdown("""
    <style>
    .footer {
        text-align: center;
        font-size: 14px;
        padding: 20px;
        background-color: #222222; /* Darker background */
        color: white; /* White text */
        border-top: 2px solid #444444; /* Subtle border on top */
        position: fixed;
        bottom: 0;
        width: 100%;
        left: 0;
        box-shadow: 0 -2px 5px rgba(0, 0, 0, 0.2); /* Subtle shadow for better separation */
    }

    .footer p {
        margin: 0;
    }

    .footer a {
        margin: 0 15px;
        text-decoration: none;
        color: white;
        font-weight: bold;
        font-size: 16px;
    }

    .footer a:hover {
        text-decoration: underline;
    }

    .footer img {
        width: 30px;
        height: 30px;
        margin: 0 10px;
        transition: transform 0.3s ease;
    }

    .footer img:hover {
        transform: scale(1.2); /* Hover effect for icons */
    }
    </style>
    <div class="footer">
        <p>Built by Im_DEV | 
        <a href="https://www.linkedin.com/in/dev-ice" target="_blank">
            <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/81/LinkedIn_icon.svg/1200px-LinkedIn_icon.svg.png" alt="LinkedIn">
        </a>
        <a href="https://github.com/dev-comett" target="_blank">
            <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub">
        </a>
        </p>
    </div>
""", unsafe_allow_html=True)
