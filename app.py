from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re
from urllib.parse import urlparse, unquote

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

# --- Helper Function ---
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = []

    # Length
    features.append(len(url))

    # Special chars
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('%'))
    features.append(url.count('.'))

    # Suspicious patterns
    features.append(1 if '//' in url[8:] else 0)
    features.append(1 if '@' in url else 0)
    features.append(1 if '%00' in url else 0)

    return features

@app.route("/")
def home():
    return "Backend running on Render"

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        url = data.get("url", "").strip().lower()

        if not url.startswith("http"):
            return jsonify({"status": "Invalid URL ❌", "score": 0, "reasons": ["Enter valid URL"]})

        url = unquote(url)
        parsed = urlparse(url)
        domain = parsed.netloc

        reasons = []
        score = 0

        # --- 1. Suspicious patterns (IMPORTANT for your test cases) ---
        if '@' in url:
            reasons.append("Contains @ symbol (phishing trick)")
            score += 90

        if '%00' in url:
            reasons.append("Contains encoded characters (%00 attack)")
            score += 90

        if '//' in url[8:]:
            reasons.append("Double slash redirection detected")
            score += 80

        # --- 2. Fake domain trick ---
        if any(brand in domain and not domain.endswith(f"{brand}.com") for brand in trusted_brands):
            reasons.append("Brand impersonation detected")
            score += 95

        # --- 3. Risky TLD ---
        if any(domain.endswith(tld) for tld in risky_tlds):
            reasons.append("Suspicious domain extension")
            score += 80

        # --- 4. Keywords ---
        if any(word in url for word in high_risk_keywords):
            reasons.append("Contains phishing keywords")
            score += 70

        # --- 5. ML Model ---
        ml_score = 0
        if model and vectorizer:
            try:
                vec = vectorizer.transform([url])
                ml_score = model.predict_proba(vec)[0][1] * 100
            except:
                pass

        final_score = max(score, ml_score)
        if final_score > 100:
            final_score = 100

        # --- Final Status ---
        if final_score > 75:
            status = "Phishing 🚨"
        elif final_score > 45:
            status = "Suspicious ⚠️"
        else:
            status = "Legitimate ✅"

        return jsonify({
            "status": status,
            "score": round(final_score, 2),
            "reasons": reasons if reasons else ["No major issues"]
        })

    except Exception as e:
        return jsonify({
            "status": "Error ⚠️",
            "score": 0,
            "reasons": ["Server error"]
        }), 500


if __name__ == "__main__":
    app.run()change this code
