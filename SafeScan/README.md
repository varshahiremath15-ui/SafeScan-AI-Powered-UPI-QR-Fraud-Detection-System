# SafeScan – AI-Powered UPI/QR Fraud Detection System

SafeScan is a working cybersecurity web application designed to evaluate the risk of UPI payment strings, web payment URLs, and QR code transactions before a user authorizes a transfer.

The system uses a Scikit-Learn **Random Forest Classifier** trained on structural, lexical, and behavioral security features to output a calibrated continuous risk score (0–100) and classify transactions into **SAFE**, **SUSPICIOUS**, or **HIGH RISK** with explicit reasons and safety recommendations.

---

## 1. Project Folder Structure

```
SafeScan/
│
├── app.py                   # Flask web server, routing, QR decode endpoints, & views
├── train_model.py           # Random Forest training script & evaluation pipeline
├── predict.py               # Risk scoring engine (0-100 score calculation & prediction)
├── feature_extraction.py    # 19 security features extraction & domain parsing
├── database.py              # SQLite database layer for scan persistence
├── requirements.txt         # Python dependencies
├── README.md                # System documentation, commands, & test vectors
├── safescan.db              # SQLite database (auto-generated)
│
├── dataset/
│   └── dataset.csv          # Demonstration dataset with genuine & fraudulent payloads
│
├── models/
│   └── fraud_model.pkl      # Serialized Random Forest model & feature columns
│
├── templates/
│   ├── index.html           # Professional SafeScan landing page & radar overview
│   ├── analyze.html         # UPI/URL manual input & QR image drag-and-drop form
│   ├── result.html          # Risk score gauge, reasons, recommendations, & features
│   └── history.html         # Audit log table and database search
│
└── static/
    ├── css/
    │   └── style.css        # Cybersecurity styling, gauges, & responsive layout
    └── js/
        └── script.js        # QR image preview, drag-and-drop, sample fill, & search
```

---

## 2. Working Flow Architecture

```
User enters UPI/URL OR uploads QR image
                   ↓
        Extract payment information
                   ↓
        Extract 19 security features
                   ↓
        Random Forest ML model
                   ↓
     Calculate calibrated risk score (0-100)
                   ↓
         SAFE / SUSPICIOUS / FRAUD
                   ↓
     Show reasons, recommendations, & save to SQLite
```

---

## 3. Dataset Format (`dataset/dataset.csv`)

> **DATASET NOTICE**: The dataset provided in `dataset/dataset.csv` is a demonstration dataset created to allow the machine learning pipeline to train and run out-of-the-box. It is **NOT** claimed to be real-world proprietary banking data. You can easily replace `dataset.csv` with your own real-world labeled dataset anytime.

### CSV Specification:
```csv
raw_input,label
"upi://pay?pa=store.billing@okhdfcbank&pn=FreshMart%20Groceries&mc=5411&am=450.00&cu=INR",0
"http://bit.ly/claim-googlepay-reward-2024",1
"http://192.168.1.105/paytm-kyc-verify-urgent.php?pa=fakehelp@okaxis&am=10000",1
```

- `raw_input`: The full UPI payment URI, website URL, or payment link.
- `label`:
  - `0`: Legitimate / Safe payment transaction
  - `1`: Malicious / Fraudulent / Phishing payment request

---

## 4. Extracted Security Features (19 Dimensions)

The feature extractor extracts the following vectors for the ML model:

1. **`url_length`**: Total character count of the input.
2. **`num_dots`**: Count of periods (`.`).
3. **`num_hyphens`**: Count of hyphens (`-`).
4. **`num_special_chars`**: Count of non-standard characters outside normal URL delimiters.
5. **`has_at_symbol`**: Presence of `@` (crucial for VPA validation).
6. **`is_ip_address`**: Detection of raw IPv4 host instead of verified domain.
7. **`is_https`**: Verification of HTTPS encrypted web protocol.
8. **`num_parameters`**: Number of query string parameters.
9. **`suspicious_keyword_count`**: Count of deceptive lure keywords (`cashback`, `refund`, `kyc`, `urgent`, `blocked`, `lottery`, `winner`, `apk`).
10. **`is_upi_scheme`**: Detection of standard `upi://` protocol.
11. **`has_valid_vpa_format`**: Verification against NPCI banking PSP handles (`okhdfcbank`, `oksbi`, `okaxis`, `paytm`, `ybl`, etc.).
12. **`vpa_length`**: Character length of the payee VPA.
13. **`has_amount_param`**: Presence of pre-filled transaction debit parameter (`am`).
14. **`amount_value`**: Parsed monetary value of the debit request.
15. **`has_unusual_characters`**: Obfuscated hex or excessive percent encoding.
16. **`num_subdomains`**: Count of nested subdomain levels.
17. **`is_shortened_url`**: Flag for URL shorteners (`bit.ly`, `tinyurl.com`, `is.gd`, etc.).
18. **`has_payee_name`**: Presence of payee name (`pn`) parameter.
19. **`is_high_risk_keyword_present`**: Binary trigger for deceptive urgency cues.

---

## 5. Risk Score & Prediction Scale

The Random Forest model produces class probabilities $[P(\text{safe}), P(\text{fraud})]$. The probability $P(\text{fraud})$ is scaled into an integer score from **0 to 100**:

- **`0 – 30` = SAFE**: Clean structure, verified banking handle, no phishing keywords.
- **`31 – 70` = SUSPICIOUS**: Concealed destination, promotional lures, or unverified handles.
- **`71 – 100` = HIGH RISK / FRAUD**: Direct IP host, plain HTTP, urgent KYC threats, or fraudulent debit lures.

---

## 6. Installation Commands

Clone the repository and install the requirements:

```bash
cd SafeScan
pip install -r requirements.txt
```

*(On Debian/Ubuntu Linux, system libraries for OpenCV and ZBar can be installed with: `sudo apt-get install -y libzbar0 python3-opencv`)*

---

## 7. Model Training Command

Train the Random Forest classifier:

```bash
python train_model.py
```

Output:
```
============================================================
SafeScan – Random Forest Model Training
============================================================
[*] Loading dataset from: .../dataset/dataset.csv
[*] Loaded 50 samples across classes:
[*] Extracting features for all inputs...
[*] Extracted 19 security features per sample.
[*] Training Random Forest Classifier...
[+] Model Evaluation Results:
    - Accuracy:  100.00%
    - ROC AUC:   1.0000
[SUCCESS] Trained model successfully saved to: models/fraud_model.pkl
============================================================
```

---

## 8. Flask Run Command

To start the web application:

```bash
python app.py
```

The application will start on `http://127.0.0.1:3000` (or `http://0.0.0.0:3000`).

---

## 9. Test Inputs & Expected Outputs

### Test Input 1: Legitimate Merchant UPI
- **Input**:
  ```
  upi://pay?pa=store.billing@okhdfcbank&pn=FreshMart%20Groceries&mc=5411&tid=TXN987213&tr=REF102938&am=450.00&cu=INR
  ```
- **Expected Prediction**: `SAFE`
- **Expected Risk Score**: `0 – 20 / 100`
- **Expected Recommendation**: "Verified structure: The payment link conforms to standard UPI and secure URL standards. Proceed normally while verifying the recipient name on your payment screen."

### Test Input 2: Suspicious URL Shortener Lure
- **Input**:
  ```
  http://bit.ly/claim-googlepay-reward-2024
  ```
- **Expected Prediction**: `SUSPICIOUS`
- **Expected Risk Score**: `50 – 70 / 100`
- **Reasons**:
  - URL shortener used to conceal the genuine destination payment endpoint.
  - Insecure plain HTTP connection detected.
  - Deceptive lures/keywords detected: reward, claim.
- **Expected Recommendation**: "Caution advised: Verify the recipient's phone number and genuine identity directly before authorizing any transaction in your UPI app."

### Test Input 3: High-Risk Raw IP & Urgent Phishing Threat
- **Input**:
  ```
  http://192.168.1.105/paytm-kyc-verify-urgent.php?pa=fakehelp@okaxis&am=10000
  ```
- **Expected Prediction**: `HIGH RISK`
- **Expected Risk Score**: `85 – 100 / 100`
- **Reasons**:
  - Raw IP address used instead of legitimate verified domain name.
  - Insecure plain HTTP connection detected (lacks SSL/TLS encryption).
  - Deceptive lures/keywords detected: kyc, urgent.
  - Fixed pre-filled debit amount of ₹10,000.00 embedded into payment request.
- **Expected Recommendation**: "DO NOT PAY. This payment link exhibits multiple high-confidence fraudulent patterns and is likely designed to steal funds or credentials."

---

## 10. QR Image Upload & Decoding

1. Upload any QR code image (PNG, JPG, WEBP).
2. The server processes the image via OpenCV `QRCodeDetector` (with PyZbar fallback).
3. The encoded UPI payment URI is extracted from the QR matrix.
4. The exact same feature extraction and Random Forest prediction pipeline is run on the decoded string.

---

## 11. Troubleshooting

1. **`ModuleNotFoundError: No module named 'sklearn'`**:
   Run `pip install -r requirements.txt`.
2. **`zbar / OpenCV shared library error`**:
   Install Debian dependencies: `sudo apt-get install -y libzbar0 python3-opencv`.
3. **Model file missing**:
   `predict.py` automatically detects if `models/fraud_model.pkl` is missing and runs `train_model.train()` automatically on first request.
4. **Port collision on 3000**:
   You can change the listening port using `PORT=5000 python app.py`.
