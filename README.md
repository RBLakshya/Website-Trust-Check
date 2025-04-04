# Website Trust Check

A user-friendly bash script that helps you verify website security and trustworthiness at a glance. Perfect for non-technical users who want to quickly check if a website is safe to use.

## Features:

- **WHOIS Analysis** - Check registrar details, domain age, and ownership information
- **SSL Certificate Check** - Verify certificate validity and security status
- **DNS Configuration** - Review DNS records with security warnings
- **Security Headers** - Detect missing security protections (CSP, HSTS, etc.)
- **Threat Intelligence** - Google Safe Browsing status + optional VirusTotal integration
- **Geolocation** - Identify where the website is physically hosted
- **Visual Risk Indicators** - Color-coded results for instant understanding

## Installation:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Website-Trust-Check.git

2. Execute at files:
   ```bash
   cd Website-Trust-Check
   chmod +x WebTrustCheck.sh

   ./WebTrustCheck.sh

4. Execute from Anywhere:
   ```bash
   cd Website-Trust-Check
   sudo mv WebTrustCheck.sh /usr/local/bin/webtrustcheck && sudo chmod +x /usr/local/bin/webtrustcheck

   # Now Execute anywhere with:
   webtrustcheck

