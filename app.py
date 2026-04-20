from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# --- 1. Load AI Models Safely ---
base_path = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_path, "phishing_model.pkl")
vectorizer_path = os.path.join(base_path, "vectorizer.pkl")

try:
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
        print("✅ AI Engine Online: Models Loaded successfully.")
    else:
        model = None
        vectorizer = None
        print("❌ ERROR: Model files (.pkl) not found in BACKEND folder.")
except Exception as e:
    model = None
    vectorizer = None
    print(f"❌ ERROR: Could not load models: {e}")

# --- 2. Detection Configuration ---
legitimate_sites = ["google.com", "wikipedia.org", "apple.com", "amazon.com", "microsoft.com","aceec.ac.in"]
high_risk_keywords = ["movierulz", "free-movies", "torrent", "cracked", "login-verify","go0gle","faceb0ok"]
risky_tlds = [".theater", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top"]
trusted_brands = ["whatsapp", "facebook", "paypal", "instagram", "bank", "netflix"]

# --- 3. Root Route (for testing on browser) ---
@app.route("/")
def home():
    return "Phishing Detection API is Running 🚀"

# --- 4. Main Analyze Route ---
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"status": "No URL provided ❌", "score": 0, "reasons": ["Empty request sent."]}), 400
            
        url = data.get("url", "").lower().strip()

        # A. Basic Validation
        if not url.startswith("http") or "." not in url or len(url) < 8:
            return jsonify({
                "status": "Invalid URL ❌", 
                "score": 0, 
                "reasons": ["Please enter a full URL starting with http:// or https://"]
            })

        parsed = urlparse(url)
        domain = parsed.netloc

        # 🔥 FIXED: Proper whitelist (no substring mistake)
        if domain in legitimate_sites:
            return jsonify({
                "status": "Legitimate ✅", 
                "score": 0, 
                "reasons": ["Verified Trusted Domain"]
            })

        reasons = []
        h_score = 0

        # --- NEW IMPORTANT TEST CASE HANDLING ---

        # 1. Double dots
        if ".." in url:
            reasons.append("Invalid domain format (double dots)")
            h_score += 85

        # 2. @ symbol
        if "@" in url:
            reasons.append("Detected '@' symbol masking")
            h_score += 90

        # 3. Too many subdomains
        if domain.count('.') >= 3:
            reasons.append("Excessive subdomains (possible spoofing)")
            h_score += 70

        # 4. IP address detection
        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            reasons.append("IP address used instead of domain")
            h_score += 80

        # --- EXISTING LOGIC ---

        # High-Risk Keywords
        if any(kw in url for kw in high_risk_keywords):
            reasons.append("Contains high-risk/piracy keywords")
            h_score += 85

        # High-Risk TLDs
        if any(url.endswith(tld) or f"{tld}/" in url for tld in risky_tlds):
            reasons.append("Unusual or high-risk domain extension")
            h_score += 80

        # Brand Impersonation
        for brand in trusted_brands:
            if brand in url and not (url.endswith(f"{brand}.com") or url.endswith(f"{brand}.org")):
                reasons.append(f"Potential {brand.capitalize()} Impersonation")
                h_score += 90

        # --- AI Prediction ---
        ml_prob = 0
        if model and vectorizer:
            try:
                url_vec = vectorizer.transform([url])
                ml_prob = model.predict_proba(url_vec)[0][1] * 100
            except Exception as e:
                print(f"AI Transform Error: {e}")

        # --- Final Score ---
        final_score = max(ml_prob, h_score)
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
            "reasons": reasons if reasons else ["No major anomalies detected."]
        })

    except Exception as e:
        print(f"⚠️ Server Crash Prevented: {e}")
        return jsonify({
            "status": "Analysis Error ❌", 
            "score": 0, 
            "reasons": ["Internal engine error occurred."]
        }), 500


# --- 5. Render Deployment Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))