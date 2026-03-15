"""
train_models.py
---------------
Trains DUAL ML models for the Phishing Attack Defender:

1. URL model (existing): Classifies URLs from dataset.csv → model.pkl
2. NEW Email model: Classifies email text from email_dataset.csv → email_model.pkl

Usage: python train_models.py
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

# Existing URL features
from feature_extractor import FEATURE_NAMES, extract_features

# New email features
from email_feature_extractor import EMAIL_FEATURE_NAMES, extract_email_features

print("🤖 Training DUAL Phishing Detection Models\n" + "="*60)

# ── 1. Train URL Model (existing workflow) ───────────────────────────────────
print("\n📡 [Phase 1] Training URL Classifier...")
dataset_path = os.path.join(os.path.dirname(__file__), 'dataset.csv')
df_url = pd.read_csv(dataset_path)
print(f"   Loaded {len(df_url)} URL samples")

X_url = pd.DataFrame([extract_features(row['url']) for _, row in df_url.iterrows()], 
                     columns=FEATURE_NAMES)
y_url = df_url['label']

X_url_train, X_url_test, y_url_train, y_url_test = train_test_split(
    X_url, y_url, test_size=0.2, random_state=42, stratify=y_url
)

url_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
url_model.fit(X_url_train, y_url_train)

url_accuracy = accuracy_score(y_url_test, url_model.predict(X_url_test))
print(f"   ✅ URL Model Accuracy: {url_accuracy*100:.1f}%")
print("   📊 URL Classification Report:")
print(classification_report(y_url_test, url_model.predict(X_url_test)))

# ── 2. Train Email Model (NEW) ────────────────────────────────────────────────
print("\n📧 [Phase 2] Training Email Classifier...")
email_dataset_path = os.path.join(os.path.dirname(__file__), 'email_dataset.csv')
df_email = pd.read_csv(email_dataset_path)
print(f"   Loaded {len(df_email)} email samples")

X_email = pd.DataFrame([extract_email_features(row['email_text']) for _, row in df_email.iterrows()], 
                       columns=EMAIL_FEATURE_NAMES)
y_email = df_email['label']

X_email_train, X_email_test, y_email_train, y_email_test = train_test_split(
    X_email, y_email, test_size=0.2, random_state=42, stratify=y_email
)

email_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
email_model.fit(X_email_train, y_email_train)

email_accuracy = accuracy_score(y_email_test, email_model.predict(X_email_test))
print(f"   ✅ Email Model Accuracy: {email_accuracy*100:.1f}%")
print("   📊 Email Classification Report:")
print(classification_report(y_email_test, email_model.predict(X_email_test)))

# ── 3. Feature Importance ─────────────────────────────────────────────────────
print("\n🔍 Feature Importances:")
print("\n📡 URL Model (Top 5):")
url_importance = pd.DataFrame({
    'feature': FEATURE_NAMES,
    'importance': url_model.feature_importances_
}).sort_values('importance', ascending=False).head()

for _, row in url_importance.iterrows():
    print(f"   {row['feature']:<20} {row['importance']:.4f}")

print("\n📧 Email Model (Top 5):")
email_importance = pd.DataFrame({
    'feature': EMAIL_FEATURE_NAMES,
    'importance': email_model.feature_importances_
}).sort_values('importance', ascending=False).head()

for _, row in email_importance.iterrows():
    print(f"   {row['feature']:<20} {row['importance']:.4f}")

# ── 4. Save Both Models ──────────────────────────────────────────────────────
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
email_model_path = os.path.join(os.path.dirname(__file__), 'email_model.pkl')

with open(model_path, 'wb') as f:
    pickle.dump(url_model, f)

with open(email_model_path, 'wb') as f:
    pickle.dump(email_model, f)

print(f"\n💾 Models saved:")
print(f"   📡 URL model → {model_path}")
print(f"   📧 Email model → {email_model_path}")

print("\n🎉 DUAL MODEL TRAINING COMPLETE!")
print("   Ready for backend integration.")

