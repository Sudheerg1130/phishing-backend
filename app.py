from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher  # Required for similarity checking

app = Flask(__name__)
CORS(app)

# --- Load Models ---
base_path = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_path, "phishing_model.pkl")
vectorizer_path = os.path.join(base_path, "vectorizer.pkl")

try:
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
except:
    model = None
    vectorizer = None

# --- Detection Lists ---
legitimate_sites = ["google.com", "wikipedia.org", "apple.com", "amazon.com", "microsoft.com"]
high_risk_keywords = ["movierulz", "free", "verify", "login", "secure", "account", "update", "bank"]
risky_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click", ".ru", ".info"]
trusted_brands = ["google", "facebook", "amazon", "netflix", "paypal", "instagram", "bank", "microsoft", "icici", "axis"]

# --- Helper Functions ---
def is_similar(a, b):
    """Calculates how similar two strings are (0.0 to 1.0)"""
    return SequenceMatcher(None, a, b).ratio()

@app.route("/")
def home():
    return "Backend running on Render"

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        url = data.get("url", "").strip().lower()

        # Basic Validation
        if not url.startswith("http"):
            return jsonify({"status": "Invalid URL ❌", "score": 0, "reasons": ["Enter valid URL (starting with http/https)"]})

        url = unquote(url)
        parsed = urlparse(url)
        domain = parsed.netloc

        # Extract main domain name (e.g., 'go0gle' from 'www.go0gle.com')
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            # Handle cases like 'google.com' or 'www.google.com'
            main_domain = domain_parts[-2]
        else:
            main_domain = domain

        reasons = []
        score = 0

        # --- 1. Look-alike / Typosquatting Check (The "go0gle" Fix) ---
        for brand in trusted_brands:
            similarity = is_similar(main_domain, brand)
            
            # Match: 'go0gle' vs 'google' (Similarity will be ~0.8)
            if 0.7 < similarity < 1.0:
                reasons.append(f"Look-alike domain detected (resembles {brand})")
                score += 95
            
            # Match: brand name exists but isn't the official domain
            elif brand in domain and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
                reasons.append(f"Potential brand impersonation: {brand}")
                score += 85

        # --- 2. Character Substitution Check ---
        if '0' in main_domain and 'o' not in main_domain:
            reasons.append("Suspicious numeric substitution (0 for o)")
            score += 70
        if '1' in main_domain and 'l' not in main_domain:
            reasons.append("Suspicious numeric substitution (1 for l)")
            score += 70

        # --- 3. Suspicious URL Patterns ---
        if '@' in url:
            reasons.append("Contains @ symbol (used to hide real domain)")
            score += 90
        if '//' in url[8:]:
            reasons.append("Double slash redirection detected")
            score += 80
        if any(domain.endswith(tld) for tld in risky_tlds):
            reasons.append("Suspicious Top-Level Domain (TLD)")
            score += 80
        if any(word in url for word in high_risk_keywords):
            reasons.append("Contains high-risk keywords")
            score += 60

        # --- 4. ML Model Score ---
        ml_score = 0
        if model and vectorizer:
            try:
                vec = vectorizer.transform([url])
                # Probability of being Phishing (class 1)
                ml_score = model.predict_proba(vec)[0][1] * 100
            except:
                pass

        # Calculate final score (Max of manual rules or ML)
        final_score = max(score, ml_score)
        if final_score > 100:
            final_score = 100

        # --- 5. Determine Final Status ---
        if final_score > 75:
            status = "Phishing 🚨"
        elif final_score > 40:
            status = "Suspicious ⚠️"
        else:
            status = "Legitimate ✅"

        return jsonify({
            "status": status,
            "score": round(final_score, 2),
            "reasons": reasons if reasons else ["No major security issues detected"]
        })

    except Exception as e:
        return jsonify({"status": "Error ⚠️", "score": 0, "reasons": [str(e)]}), 500

if __name__ == "__main__":
    app.run()
