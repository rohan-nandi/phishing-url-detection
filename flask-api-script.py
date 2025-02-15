# Flask API setup7
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
import joblib

# Function to extract URL-based features
def extract_url_features(url):
    parsed_url = urlparse(url)
    
    features = {
        "URLLength": len(url),
        "DomainLength": len(parsed_url.netloc),
        "IsDomainIP": parsed_url.netloc.replace('.', '').isdigit(),
        "TLD": parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else 'unknown',
        "NoOfSubDomain": len(parsed_url.netloc.split('.')) - 2,
        "IsHTTPS": int(url.startswith("https")),
        "NoOfDigits": sum(c.isdigit() for c in url),
        "NoOfSpecialChars": sum(c in "!@#$%^&*()-_=+[]{};:'\"<>,.?/" for c in url),
        "NoOfHyphens": url.count("-"),
    }

    return features

# Function to extract HTML-based features
def extract_html_features(url):
    try:
        response = requests.get(url, timeout=5)
        # Check if the response's Content-Type is HTML
        content_type = response.headers.get('Content-Type', '')
        if 'html' in content_type.lower():
            soup = BeautifulSoup(response.text, 'html.parser')
        else:
            soup = BeautifulSoup("", 'html.parser')

        features = {
            "HasTitle": int(bool(soup.title)),
            "HasFavicon": int(bool(soup.find("link", rel="icon"))),
            "HasForm": int(bool(soup.find("form"))),
            "HasJavaScript": int(bool(soup.find("script"))),
            "HasIframe": int(bool(soup.find("iframe"))),
            "HasMetaRedirect": int(bool(soup.find("meta", attrs={"http-equiv": "refresh"}))),
            "HasExternalLinks": int(any(a['href'].startswith('http') for a in soup.find_all('a', href=True))),
        }

    except:
        features = {
            "HasTitle": 0, "HasFavicon": 0, "HasForm": 0, "HasJavaScript": 0,
            "HasIframe": 0, "HasMetaRedirect": 0, "HasExternalLinks": 0
        }

    return features

# Function to extract derived features
def extract_derived_features(url):
    features = {
        "CharContinuationRate": sum(1 for c in url if c.isalpha()) / len(url) if len(url) > 0 else 0,
        "TLDLegitimateProb": 0.01,  # Placeholder (can be computed from dataset)
    }
    return features

# Function to extract all features dynamically
def extract_features(url):
    url_features = extract_url_features(url)
    html_features = extract_html_features(url)
    derived_features = extract_derived_features(url)

    return {**url_features, **html_features, **derived_features}

app = Flask(__name__)
model = joblib.load("phishing_best_model.pkl")
feature_columns = joblib.load("feature_columns.pkl")

# Load TLD mapping if it exists; if not, use an empty mapping
try:
    tld_mapping = joblib.load("tld_mapping.pkl")
except Exception:
    tld_mapping = {}

# Home route to serve the web page
@app.route('/')
def home():
    return render_template('index.html')

# Optional: favicon route to handle favicon requests gracefully
@app.route("/favicon.ico")
def favicon():
    return "", 204

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_features(url)

    # If the model expects TLD_Frequency, compute it here
    if "TLD_Frequency" in feature_columns:
        # Get the TLD from features (default to "unknown" if missing)
        tld = features.get("TLD", "unknown")
        # Look up the frequency from the training mapping (default to 0.0 if not found)
        features["TLD_Frequency"] = tld_mapping.get(tld, 0.0)
        # Remove raw TLD if present, as the model doesn't expect it
        features.pop("TLD", None)
    
    # Form a DataFrame using the expected feature columns
    try:
        df_features = pd.DataFrame([features])[feature_columns]
    except KeyError as e:
        return jsonify({"error": f"Missing expected feature: {e}"}), 500
    
    # Make prediction
    prediction = model.predict(df_features)[0]
    result = "Legitimate" if prediction == 1 else "Phishing"

    return jsonify({"url": url, "result": result})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', use_reloader=False)