import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load data
data = pd.read_csv("urls.csv")

# ADVANCED: Use character-level analysis (ngrams)
# This detects patterns like "secure-login" or "v-e-r-i-f-y"
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
X = vectorizer.fit_transform(data["url"])
y = data["label"]

# Train a more powerful model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save files
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Advanced Model & Vectorizer Saved!")