"""
train_model.py
--------------
Trains a Random Forest classifier to detect phishing URLs.

Steps:
    1. Load the labelled dataset (dataset.csv)
    2. Extract features from every URL
    3. Split data into training and test sets
    4. Train a RandomForestClassifier
    5. Evaluate and print accuracy + classification report
    6. Save the trained model to model.pkl
"""

import os
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

# Import our custom feature extraction utilities
from feature_extractor import FEATURE_NAMES, extract_features

# ── 1. Load dataset ──────────────────────────────────────────────────────────
DATASET_PATH = os.path.join(os.path.dirname(__file__), 'dataset.csv')

print(f"[*] Loading dataset from: {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)

print(f"[*] Total samples : {len(df)}")
print(f"[*] Class distribution:\n{df['label'].value_counts().rename({0: 'Legitimate', 1: 'Phishing'})}\n")

# ── 2. Feature extraction ────────────────────────────────────────────────────
print("[*] Extracting features from URLs …")

# Apply extract_features to every URL row; result is a list of feature vectors
feature_matrix = df['url'].apply(extract_features).tolist()

# Convert to a Pandas DataFrame with named columns for readability
X = pd.DataFrame(feature_matrix, columns=FEATURE_NAMES)
y = df['label']

print(f"[*] Feature matrix shape: {X.shape}")
print(f"[*] Feature columns: {list(X.columns)}\n")

# ── 3. Train / test split ────────────────────────────────────────────────────
# 80 % training, 20 % testing; stratify keeps class balance in both splits
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"[*] Training samples : {len(X_train)}")
print(f"[*] Test samples     : {len(X_test)}\n")

# ── 4. Train the model ───────────────────────────────────────────────────────
print("[*] Training RandomForestClassifier …")

model = RandomForestClassifier(
    n_estimators=100,   # number of decision trees in the forest
    max_depth=None,     # grow trees until leaves are pure
    random_state=42,    # reproducible results
    n_jobs=-1           # use all available CPU cores
)

model.fit(X_train, y_train)
print("[+] Training complete.\n")

# ── 5. Evaluate the model ────────────────────────────────────────────────────
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"[+] Test Accuracy : {accuracy * 100:.2f}%\n")

print("[+] Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# Feature importance — useful for understanding the model
importances = model.feature_importances_
sorted_idx  = np.argsort(importances)[::-1]

print("[+] Feature Importances (most -> least influential):")
for i in sorted_idx:
    print(f"    {FEATURE_NAMES[i]:<22} {importances[i]:.4f}")

# ── 6. Save the model ────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')

with open(MODEL_PATH, 'wb') as f:
    pickle.dump(model, f)

print(f"\n[+] Model saved to: {MODEL_PATH}")
