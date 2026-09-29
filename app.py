"""
SafeScan – Root Entry Point
Exposes app and routes for direct root execution or serverless platforms.
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SAFESCAN_DIR = os.path.join(CURRENT_DIR, 'SafeScan')

if SAFESCAN_DIR not in sys.path:
    sys.path.insert(0, SAFESCAN_DIR)

from SafeScan.app import app

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SafeScan Web Server')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 3000)))
    parser.add_argument('--host', type=str, default='0.0.0.0')
    args, _ = parser.parse_known_args()

    print(f"[*] Starting SafeScan server on {args.host}:{args.port}...")
    app.run(host=args.host, port=args.port, debug=False)
