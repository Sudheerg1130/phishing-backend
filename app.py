from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher

app = Flask(__name__)
CORS(app)

base_path = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_path, "phishing_model.pkl")
vectorizer_path = os.path.join(base_path, "vectorizer.pkl")

try:
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
except:
    model = None
    vectorizer = None

legitimate_sites = ["google.com", "wikipedia.org", "apple.com", "amazon.com", "microsoft.com"]
high_risk_keywords = ["movierulz", "free", "verify", "login", "secure", "account", "update", "bank"]
risky_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click", ".ru", ".info"]
trusted_brands = ["google", "facebook", "amazon", "netflix", "paypal", "instagram", "bank", "microsoft", "icici", "axis"]

def is_similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

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
        domain_parts = domain.split('.')
        main_domain = domain_parts[-2] if len(domain_parts) > 1 else domain
        reasons = []
        score = 0
        for brand in trusted_brands:
            similarity = is_similar(main_domain, brand)
            if 0.7 < similarity < 1.0:
                reasons.append(f"Look-alike domain detected (resembles {brand})")
                score += 95
            elif brand in domain and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
                reasons.append(f"Unauthorized use of {brand} brand")
                score += 85
        if '@' in url:
            reasons.append("Contains @ symbol (phishing trick)")
            score += 90
        if '0' in main_domain and 'o' not in main_domain:
            reasons.append("Numeric substitution detected (0 for o)")
            score += 75
        if '%00' in url:
            reasons.append("Contains encoded characters (%00 attack)")
            score += 90
        if '//' in url[8:]:
            reasons.append("Double slash redirection detected")
            score += 80
        if any(domain.endswith(tld) for tld in risky_tlds):
            reasons.append("Suspicious domain extension")
            score += 80
        if any(word in url for word in high_risk_keywords):
            reasons.append("Contains phishing keywords")
            score += 70
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
            "reasons": [str(e)]
        }), 500

if __name__ == "__main__":
    app.run()
