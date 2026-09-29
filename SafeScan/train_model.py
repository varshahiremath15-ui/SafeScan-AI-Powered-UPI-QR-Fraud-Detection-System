"""
Model Training Script for SafeScan
Trains a RandomForestClassifier from scikit-learn on extracted security features.
Outputs trained model to models/fraud_model.pkl.
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
import joblib

# Ensure current directory is in Python path for local module imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from feature_extraction import extract_features, FEATURE_COLUMNS

DATASET_PATH = os.path.join(CURRENT_DIR, 'dataset', 'dataset.csv')
MODEL_DIR = os.path.join(CURRENT_DIR, 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'fraud_model.pkl')

def train():
    print("=" * 60)
    print("SafeScan – Random Forest Model Training")
    print("=" * 60)
    
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    print(f"[*] Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH, comment='#')
    
    # Clean whitespace and empty entries
    df = df.dropna(subset=['raw_input', 'label'])
    df['raw_input'] = df['raw_input'].astype(str).str.strip()
    df['label'] = df['label'].astype(int)
    
    print(f"[*] Loaded {len(df)} samples across classes:")
    print(df['label'].value_counts().to_dict())

    # Extract features for all dataset samples
    print("[*] Extracting features for all inputs...")
    X_rows = []
    y = df['label'].values

    for idx, row in df.iterrows():
        raw_text = row['raw_input']
        feat_res = extract_features(raw_text)
        X_rows.append(feat_res['feature_vector'])

    X = pd.DataFrame(X_rows, columns=FEATURE_COLUMNS)

    print(f"[*] Extracted {X.shape[1]} security features per sample.")

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"[*] Training Random Forest Classifier on {len(X_train)} samples, testing on {len(X_test)} samples...")

    # Initialize RandomForestClassifier with robust hyper-parameters
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42,
        class_weight='balanced'
    )

    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob) if len(np.unique(y_test)) > 1 else 1.0

    print(f"\n[+] Model Evaluation Results:")
    print(f"    - Accuracy:  {acc * 100:.2f}%")
    print(f"    - ROC AUC:   {auc:.4f}")
    print("\n[+] Classification Report:\n")
    print(classification_report(y_test, y_pred, target_names=['Safe (0)', 'Fraud/Risky (1)']))

    # Feature Importance
    feature_importances = sorted(
        zip(FEATURE_COLUMNS, clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True
    )
    print("[+] Top 7 Informative Security Features:")
    for feat, imp in feature_importances[:7]:
        print(f"    - {feat:<30} {imp * 100:.2f}%")

    # Save model and metadata bundle
    os.makedirs(MODEL_DIR, exist_ok=True)
    bundle = {
        'model': clf,
        'feature_columns': FEATURE_COLUMNS,
        'training_samples': len(df),
        'accuracy': acc,
        'auc': auc
    }
    joblib.dump(bundle, MODEL_PATH)
    print(f"\n[SUCCESS] Trained model successfully saved to: {MODEL_PATH}")
    print("=" * 60)
    return bundle

if __name__ == '__main__':
    train()
