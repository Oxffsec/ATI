# Threat Intelligence Platform

A Flask-based platform that integrates with various OSINT sources to provide real-time threat intelligence. The platform checks the reputation of IP addresses and file hashes by querying APIs such as AbuseIPDB, VirusTotal, and AlienVault. It is designed to help security professionals identify malicious activity quickly and mitigate risks.

## Features
- **IP Reputation Check**: Validates IP addresses against AbuseIPDB and AlienVault to determine if they are associated with malicious activity.
- **File Hash Analysis**: Uses VirusTotal to scan file hashes for signs of malware, leveraging multiple antivirus engines to provide a comprehensive risk assessment.
- **OSINT Integration**: Aggregates threat intelligence from trusted third-party services for actionable security insights.
- **Error Handling**: Provides detailed error messages in case of API issues, ensuring clear feedback for users.

## API Integrations
This platform integrates with the following services to fetch threat intelligence:

- **AbuseIPDB**: Provides reputation data about IP addresses reported for malicious behavior.
- **VirusTotal**: Scans file hashes (e.g., SHA256) to check whether files are flagged as malicious by various antivirus engines.
- **AlienVault OTX**: Offers additional context and data for IP addresses, enriching the threat intelligence.

## Getting Started

### Prerequisites
- Python 3.x
- Flask
- Requests library
- API Keys for AbuseIPDB, VirusTotal, and AlienVault (available from their respective websites)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/threat-intelligence-platform.git
   cd threat-intelligence-platform
   ```

   
    Install the required dependencies:

pip install -r requirements.txt

Create a .env file in the root directory and add your API keys:

ABUSEIPDB_API_KEY=<your-abuseipdb-api-key>
VIRUSTOTAL_API_KEY=<your-virustotal-api-key>
ALIENVAULT_API_KEY=<your-alienvault-api-key>

Run the Flask app:

    python app.py

Usage

    Accessing the Platform: Open your browser and go to http://127.0.0.1:5000/ to view the main interface.

    Scan IPs or Hashes:
        Submit an IP address or file hash via the platform’s form.
        The platform will then fetch the associated threat intelligence from the integrated APIs and display the results.

    Error Handling: If there is an issue with the API request or input format, an error message will be shown detailing the problem.

Endpoints

    POST /scan:
    Accepts a JSON object containing either an ip or hash parameter. The response includes threat intelligence data from the integrated APIs.

    Request Body Example:

{
  "ip": "8.8.8.8"
}

or

{
  "hash": "d41d8cd98f00b204e9800998ecf8427e"
}

Response Example:

    {
      "abuseipdb": { ... },
      "alienvault": { ... },
      "virustotal": { ... }
    }

Development

    Fork the repository and make changes.
    Submit pull requests for any improvements, bug fixes, or features you'd like to add.

License

This project is licensed under the MIT License - see the LICENSE file for details.


You can copy and paste this content into your `README.md` file on GitHub!
