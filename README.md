# -SSL-TLS-Bug-Bounty-Checker
This SSL/TLS security assessment tool includes:

## Features:
1. **SSL/TLS Version Detection**: Checks for outdated and vulnerable SSL/TLS versions
2. **Certificate Analysis**: Validates certificate expiration, issuer, and signature algorithms
3. **Cipher Suite Analysis**: Detects weak cipher suites (requires nmap)
4. **HSTS Check**: Verifies HSTS implementation and configuration
5. **Security Headers**: Checks for missing security headers
6. **Vulnerability Detection**: Identifies known vulnerabilities (Heartbleed, POODLE, etc.)

## Installation Requirements:

```bash
# Install required Python packages
pip install cryptography pyOpenSSL requests

# Optional: Install nmap for cipher suite detection
# On Ubuntu/Debian:
sudo apt-get install nmap

# On macOS:
brew install nmap

# On Windows: Download from https://nmap.org/download.html
```

## Usage Examples:

```bash
# Basic scan
python3 ssl_tls_checker.py example.com

# Scan with custom port
python3 ssl_tls_checker.py example.com -p 8443

# Save results to JSON file
python3 ssl_tls_checker.py example.com -o results.json

# Increase timeout for slow websites
python3 ssl_tls_checker.py example.com -t 30

# Use more threads for faster scanning
python3 ssl_tls_checker.py example.com --threads 10
```

## Output Example:

The tool provides:
- Color-coded severity levels for vulnerabilities
- Detailed certificate information
- Missing security headers
- Recommendations for fixing issues
- JSON output for automation

## Bug Bounty Specific Features:

- Identifies misconfigurations that could lead to SSL stripping attacks
- Detects weak cipher suites that could be exploited
- Flags expired or soon-to-expire certificates
- Checks for missing security headers that could lead to various attacks
- Provides actionable recommendations for each finding

The tool is designed to be extensible - you can add more checks by creating new methods in the `SSLTLSChecker` class. Each finding is categorized by severity to help prioritize bug bounty submissions.
