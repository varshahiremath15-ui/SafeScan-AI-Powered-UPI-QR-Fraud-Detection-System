"""
Vercel Serverless Function Entry Point for SafeScan
Exposes the WSGI Flask app object for @vercel/python
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
SAFESCAN_DIR = os.path.join(ROOT_DIR, 'SafeScan')

# Insert paths to ensure clean imports of SafeScan modules
for directory in [SAFESCAN_DIR, ROOT_DIR]:
    if directory not in sys.path:
        sys.path.insert(0, directory)

from SafeScan.app import app

# Vercel WSGI entry point
# Vercel automatically exposes the `app` instance as the request handler
