/**
 * SafeScan – Client-side Interactions
 * Handles QR dropzone, file preview, live decoding, sample buttons, and history search.
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Sample inputs click-to-fill
  const sampleButtons = document.querySelectorAll('.btn-sample-fill');
  const upiInput = document.getElementById('upi_url');

  sampleButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const sampleValue = btn.getAttribute('data-sample');
      if (upiInput && sampleValue) {
        upiInput.value = sampleValue;
        upiInput.focus();
        // Visual feedback
        upiInput.classList.add('border-primary');
        setTimeout(() => upiInput.classList.remove('border-primary'), 1000);
      }
    });
  });

  // 2. QR Code Image Drag & Drop and Preview
  const dropzone = document.getElementById('qr-dropzone');
  const fileInput = document.getElementById('qr_image');
  const previewContainer = document.getElementById('qr-preview-container');
  const previewImage = document.getElementById('qr-preview-img');
  const fileNameDisplay = document.getElementById('qr-file-name');
  const qrDecodeStatus = document.getElementById('qr-decode-status');

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files && files.length > 0) {
        fileInput.files = files;
        handleFileSelect(files[0]);
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        handleFileSelect(fileInput.files[0]);
      }
    });
  }

  function handleFileSelect(file) {
    if (!file || !file.type.startsWith('image/')) {
      alert('Please upload a valid image file (PNG, JPG, JPEG, WEBP).');
      return;
    }

    if (fileNameDisplay) {
      fileNameDisplay.textContent = file.name;
    }

    // Show thumbnail
    const reader = new FileReader();
    reader.onload = (e) => {
      if (previewImage) {
        previewImage.src = e.target.result;
        
        // Instant client-side detection via browser BarcodeDetector API if available
        if ('BarcodeDetector' in window) {
          const barcodeDetector = new BarcodeDetector({ formats: ['qr_code'] });
          const imgObj = new Image();
          imgObj.src = e.target.result;
          imgObj.onload = () => {
            barcodeDetector.detect(imgObj)
              .then(barcodes => {
                if (barcodes.length > 0) {
                  const decoded = barcodes[0].rawValue;
                  if (qrDecodeStatus) {
                    qrDecodeStatus.innerHTML = `<span class="badge bg-success me-1">QR Detected</span> <code class="text-dark small">${escapeHtml(decoded.substring(0, 70))}${decoded.length > 70 ? '...' : ''}</code>`;
                  }
                  if (upiInput && !upiInput.value.trim()) {
                    upiInput.value = decoded;
                  }
                }
              })
              .catch(() => {});
          };
        }
      }
      if (previewContainer) {
        previewContainer.classList.remove('d-none');
      }
    };
    reader.readAsDataURL(file);

    // Call asynchronous decode preview API
    if (qrDecodeStatus) {
      qrDecodeStatus.innerHTML = '<span class="spinner-border spinner-border-sm text-primary me-2"></span>Extracting QR payload...';
      qrDecodeStatus.classList.remove('d-none');
    }

    const formData = new FormData();
    formData.append('qr_image', file);

    fetch('/api/decode-qr', {
      method: 'POST',
      body: formData
    })
    .then(res => res.json())
    .then(data => {
      if (qrDecodeStatus) {
        if (data.success && data.decoded_text) {
          qrDecodeStatus.innerHTML = `<span class="badge bg-success me-1">QR Decoded</span> <code class="text-dark small">${escapeHtml(data.decoded_text.substring(0, 70))}${data.decoded_text.length > 70 ? '...' : ''}</code>`;
          // If UPI input was empty, prefill with decoded text
          if (upiInput && !upiInput.value.trim()) {
            upiInput.value = data.decoded_text;
          }
        } else {
          qrDecodeStatus.innerHTML = `<span class="text-danger small">⚠️ ${escapeHtml(data.message || 'Could not decode QR code')}</span>`;
        }
      }
    })
    .catch(err => {
      if (qrDecodeStatus) {
        qrDecodeStatus.innerHTML = `<span class="text-muted small">Server will decode on submit.</span>`;
      }
    });
  }

  // 3. Form submission button loading state
  const analyzeForm = document.getElementById('analyze-form');
  const analyzeBtn = document.getElementById('btn-analyze-submit');

  if (analyzeForm && analyzeBtn) {
    analyzeForm.addEventListener('submit', () => {
      analyzeBtn.disabled = true;
      analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Extracting Features & Running Model...';
    });
  }

  // 4. Copy Report button in result page
  const copyBtn = document.getElementById('btn-copy-report');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const reportText = copyBtn.getAttribute('data-report');
      if (reportText && navigator.clipboard) {
        navigator.clipboard.writeText(reportText).then(() => {
          const originalText = copyBtn.innerHTML;
          copyBtn.innerHTML = '✓ Report Copied!';
          copyBtn.classList.replace('btn-secondary-action', 'btn-success');
          setTimeout(() => {
            copyBtn.innerHTML = originalText;
            copyBtn.classList.replace('btn-success', 'btn-secondary-action');
          }, 2500);
        });
      }
    });
  }

  // 5. History table search filter
  const historySearchInput = document.getElementById('history-search');
  const historyTable = document.getElementById('history-table');
  if (historySearchInput && historyTable) {
    historySearchInput.addEventListener('input', (e) => {
      const term = e.target.value.toLowerCase().trim();
      const rows = historyTable.querySelectorAll('tbody tr');
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
      });
    });
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
  }
});
