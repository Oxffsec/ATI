from flask import Flask, request, render_template, jsonify
import requests
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load API keys from .env file (More secure than hardcoding)
ABUSEIPDB_API_KEY = "your api key"
VIRUSTOTAL_API_KEY = "your api key"
ALIENVAULT_API_KEY = "your api key"


# Function to check IP reputation
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Error checking AbuseIPDB: {e}"}

# Function to check file/hash on VirusTotal
def check_virustotal(resource):
    url = f"https://www.virustotal.com/api/v3/files/{resource}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Error checking VirusTotal: {e}"}

# Function to fetch data from AlienVault OTX
def check_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Error checking AlienVault: {e}"}

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    result = {}

    if 'ip' in data:
        ip = data['ip']
        if not validate_ip(ip):
            return jsonify({"error": "Invalid IP address format"})
        result['abuseipdb'] = check_abuseipdb(ip)
        result['alienvault'] = check_alienvault(ip)

    if 'hash' in data:
        file_hash = data['hash']
        if not validate_hash(file_hash):
            return jsonify({"error": "Invalid hash format"})
        result['virustotal'] = check_virustotal(file_hash)
    
    return jsonify(result)

# Helper function to validate IP address format
def validate_ip(ip):
    import re
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', ip))

# Helper function to validate hash format (SHA256 example)
def validate_hash(hash_string):
    import re
    return bool(re.match(r'^[a-fA-F0-9]{64}$', hash_string))

if __name__ == '__main__':
    app.run(debug=True)
