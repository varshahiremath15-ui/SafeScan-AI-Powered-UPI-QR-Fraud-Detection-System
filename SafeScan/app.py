"""
SafeScan – AI-Powered UPI/QR Fraud Detection System
Flask Backend Application
"""

import os
import sys
import io
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from werkzeug.utils import secure_filename

# Ensure local imports work reliably
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from feature_extraction import extract_features
from predict import analyze_payment_input, get_model
from database import init_db, insert_scan, get_recent_scans, get_scan_by_id, get_scan_statistics

TEMPLATES_DIR = os.path.join(CURRENT_DIR, 'templates')
STATIC_DIR = os.path.join(CURRENT_DIR, 'static')

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR
)
app.secret_key = os.environ.get('SECRET_KEY', 'safescan-cyber-security-secret-key-2024')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp', 'gif'}

# Initialize database tables on startup
init_db()

# Preload or trigger model build
try:
    get_model()
except Exception as e:
    print(f"[!] Warning during initial model loading: {e}")

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def decode_qr_bytes(file_bytes: bytes) -> tuple[bool, str, str]:
    """
    Decodes a QR code from raw image bytes using PyZbar (primary) and OpenCV fallbacks.
    Returns (success, decoded_text, message)
    """
    if not file_bytes:
        return False, '', 'Empty image file uploaded.'

    # Attempt 1: PyZbar (high accuracy & robust decoding)
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        pil_img = Image.open(io.BytesIO(file_bytes))
        decoded_objs = decode(pil_img)
        if decoded_objs:
            decoded_text = decoded_objs[0].data.decode('utf-8', errors='ignore').strip()
            if decoded_text:
                return True, decoded_text, 'QR code successfully decoded using PyZbar engine.'
    except Exception as pyzbar_err:
        print(f"[!] PyZbar decode attempt notice: {pyzbar_err}")

    # Attempt 2: OpenCV QRCodeDetector (fallback)
    try:
        import cv2
        import numpy as np
        nparr = np.frombuffer(file_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is not None:
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img)
            if data and data.strip():
                return True, data.strip(), 'QR code successfully decoded using OpenCV engine.'

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            data, bbox, _ = detector.detectAndDecode(gray)
            if data and data.strip():
                return True, data.strip(), 'QR code successfully decoded with image preprocessing.'
    except Exception as cv_err:
        print(f"[!] OpenCV QR decode attempt notice: {cv_err}")

    return False, '', 'No valid QR code could be detected in the uploaded image. Please ensure the QR code is clearly visible and undamaged.'


# -------------------------------------------------------------
# Routes
# -------------------------------------------------------------

@app.route('/')
def index():
    """Professional SafeScan Homepage."""
    stats = get_scan_statistics()
    recent = get_recent_scans(limit=5)
    return render_template('index.html', stats=stats, recent_scans=recent)


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Analyze form and submission handler for UPI/URL text and QR image upload."""
    if request.method == 'GET':
        prefill_input = request.args.get('input', '').strip()
        return render_template('analyze.html', prefill_input=prefill_input)

    # POST request handling
    raw_input_text = request.form.get('upi_url', '').strip()
    qr_file = request.files.get('qr_image')
    decoded_from_qr = False
    qr_decode_note = ''

    # Handle QR file if provided
    if qr_file and qr_file.filename != '':
        if not allowed_file(qr_file.filename):
            flash('Invalid file format. Please upload an image (PNG, JPG, JPEG, WEBP).', 'danger')
            return redirect(url_for('analyze'))

        try:
            image_bytes = qr_file.read()
            success, qr_content, note = decode_qr_bytes(image_bytes)
            if not success:
                flash(f'QR Decoding Failed: {note}', 'danger')
                return redirect(url_for('analyze'))
            raw_input_text = qr_content
            decoded_from_qr = True
            qr_decode_note = note
        except Exception as e:
            flash(f'Error processing QR code image: {str(e)}', 'danger')
            return redirect(url_for('analyze'))

    if not raw_input_text:
        flash('Please enter a UPI ID / payment URL or upload a QR image to analyze.', 'warning')
        return redirect(url_for('analyze'))

    # Run the unified ML & feature analysis pipeline
    analysis = analyze_payment_input(raw_input_text)
    if 'error' in analysis:
        flash(analysis['error'], 'danger')
        return redirect(url_for('analyze'))

    analysis['decoded_from_qr'] = decoded_from_qr
    analysis['qr_decode_note'] = qr_decode_note

    # Persist scan to SQLite database
    scan_id = insert_scan(
        input_data=raw_input_text,
        prediction=analysis['prediction'],
        risk_score=analysis['risk_score'],
        features=analysis
    )

    return redirect(url_for('result', scan_id=scan_id))


@app.route('/result/<int:scan_id>')
def result(scan_id):
    """Result page displaying detailed analysis for a specific scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash(f'Scan report #{scan_id} not found.', 'danger')
        return redirect(url_for('analyze'))

    return render_template('result.html', scan=scan, analysis=scan['features'])


@app.route('/history')
def history():
    """Scan history page showing all audits stored in SQLite."""
    scans = get_recent_scans(limit=100)
    stats = get_scan_statistics()
    return render_template('history.html', scans=scans, stats=stats)


# -------------------------------------------------------------
# REST API Endpoints (for programmatic integration & AJAX)
# -------------------------------------------------------------

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """REST endpoint to analyze raw UPI/URL input string."""
    data = request.get_json(silent=True) or {}
    raw_input = data.get('input_data', '').strip()
    if not raw_input:
        return jsonify({'success': False, 'error': 'Missing input_data parameter'}), 400

    analysis = analyze_payment_input(raw_input)
    scan_id = insert_scan(
        input_data=raw_input,
        prediction=analysis['prediction'],
        risk_score=analysis['risk_score'],
        features=analysis
    )
    analysis['scan_id'] = scan_id
    return jsonify({'success': True, 'data': analysis})


@app.route('/api/decode-qr', methods=['POST'])
def api_decode_qr():
    """REST endpoint to decode QR image and return payload."""
    if 'qr_image' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    file = request.files['qr_image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Empty filename'}), 400
    
    img_bytes = file.read()
    success, decoded_text, note = decode_qr_bytes(img_bytes)
    return jsonify({
        'success': success,
        'decoded_text': decoded_text,
        'message': note
    })


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SafeScan Web Server')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 3000)))
    parser.add_argument('--host', type=str, default='0.0.0.0')
    args, _ = parser.parse_known_args()

    print(f"[*] Starting SafeScan server on {args.host}:{args.port}...")
    app.run(host=args.host, port=args.port, debug=False)
