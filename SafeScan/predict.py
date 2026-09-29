"""
Prediction Engine for SafeScan
Loads trained Random Forest model, runs inference on extracted features,
calculates calibrated 0-100 risk score, and maps to SAFE, SUSPICIOUS, or HIGH RISK.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from feature_extraction import extract_features, FEATURE_COLUMNS

MODEL_PATH = os.path.join(CURRENT_DIR, 'models', 'fraud_model.pkl')

_cached_model_bundle = None

def get_model():
    """
    Load or retrieve cached model bundle.
    If the model has not been trained yet, triggers automatic training first.
    """
    global _cached_model_bundle
    if _cached_model_bundle is not None:
        return _cached_model_bundle

    if not os.path.exists(MODEL_PATH):
        print(f"[*] Model file not found at {MODEL_PATH}. Initiating automatic training...")
        from train_model import train
        _cached_model_bundle = train()
        return _cached_model_bundle

    _cached_model_bundle = joblib.load(MODEL_PATH)
    return _cached_model_bundle

def analyze_payment_input(raw_input: str) -> dict:
    """
    Complete analysis pipeline:
    raw_input -> extract_features -> ML inference -> risk score (0-100) -> categorization -> reasons & recommendation
    """
    if not raw_input or not raw_input.strip():
        return {
            'error': 'Input is empty. Please provide a UPI ID, URL, or upload a QR image.'
        }

    raw_input = raw_input.strip()
    feature_data = extract_features(raw_input)
    feature_vector = [feature_data['features'][col] for col in FEATURE_COLUMNS]

    # Convert to DataFrame with feature names to match training format
    X = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)

    # Load model
    bundle = get_model()
    clf = bundle['model']

    # Predict probabilities: [P(safe), P(fraud)]
    probabilities = clf.predict_proba(X)[0]
    
    # Class 1 is Fraud / Risky
    prob_fraud = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])

    # Convert probability into 0-100 risk score
    # Baseline probability from Random Forest
    raw_risk_score = prob_fraud * 100.0

    # Ensure risk score is bounded [0, 100]
    risk_score = int(round(max(0.0, min(100.0, raw_risk_score))))

    # Categorization based on strict prompt thresholds:
    # 0–30 = SAFE
    # 31–70 = SUSPICIOUS
    # 71–100 = HIGH RISK
    if risk_score <= 30:
        prediction = 'SAFE'
        status_color = 'success'
        badge_class = 'bg-success'
        risk_level_text = 'Low Risk'
    elif risk_score <= 70:
        prediction = 'SUSPICIOUS'
        status_color = 'warning'
        badge_class = 'bg-warning text-dark'
        risk_level_text = 'Moderate Risk'
    else:
        prediction = 'HIGH RISK'
        status_color = 'danger'
        badge_class = 'bg-danger'
        risk_level_text = 'Severe Risk / Fraud Detected'

    # Human-friendly feature labels for UI
    friendly_features = {
        'URL / String Length': f"{feature_data['features']['url_length']} characters",
        'UPI Payment Protocol': 'Yes (Standard UPI URI)' if feature_data['features']['is_upi_scheme'] else 'No (Web URL / Direct text)',
        'Extracted Payee VPA': feature_data['parsed_vpa'] if feature_data['parsed_vpa'] else 'None detected',
        'Recognized Bank Handle': 'Verified Legitimate Handle' if feature_data['features']['has_valid_vpa_format'] else 'Unverified / Generic Handle',
        'Payee Display Name': feature_data['payee_name'] if feature_data['payee_name'] else 'Not provided',
        'Requested Amount': f"₹{feature_data['amount']:,.2f}" if feature_data['features']['has_amount_param'] else 'Open Amount (User specified)',
        'HTTPS Encryption': 'Secure (HTTPS)' if feature_data['features']['is_https'] else ('Insecure Plain HTTP' if raw_input.lower().startswith('http://') else 'N/A (UPI Protocol)'),
        'IP Address Usage': 'Yes (Direct IP Host)' if feature_data['features']['is_ip_address'] else 'No (Standard Domain/Scheme)',
        'URL Shortener Detected': 'Yes (Concealed destination)' if feature_data['features']['is_shortened_url'] else 'No (Direct URI)',
        'Suspicious Keywords Found': ', '.join(feature_data['matched_keywords']) if feature_data['matched_keywords'] else 'None',
        'Query Parameters Count': feature_data['features']['num_parameters'],
        'Special Characters Count': feature_data['features']['num_special_chars']
    }

    # Reasons list
    reasons = feature_data['reasons']
    if not reasons:
        if prediction == 'SAFE':
            reasons = [
                "Recognized legitimate payment structure conforming to UPI/banking standards.",
                "No deceptive phishing keywords or malicious shorteners detected.",
                "Safe payee format verified."
            ]
        else:
            reasons = ["Elevated statistical anomaly detected across combined structural features."]

    # Recommendation
    recommendation = feature_data['recommendation']

    return {
        'prediction': prediction,
        'risk_score': risk_score,
        'probability_fraud': round(prob_fraud, 4),
        'probability_safe': round(1.0 - prob_fraud, 4),
        'status_color': status_color,
        'badge_class': badge_class,
        'risk_level_text': risk_level_text,
        'input_analyzed': raw_input,
        'detected_features': friendly_features,
        'raw_features': feature_data['features'],
        'reasons': reasons,
        'recommendation': recommendation,
        'parsed_vpa': feature_data['parsed_vpa'],
        'payee_name': feature_data['payee_name'],
        'amount': feature_data['amount']
    }
