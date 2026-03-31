#!/usr/bin/env python3
"""
SSL/TLS Security Assessment Tool for Bug Bounty
Checks various SSL/TLS configurations, vulnerabilities, and security issues
"""

import ssl
import socket
import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
import sys
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import OpenSSL
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import hashlib
import warnings
from typing import Dict, List, Tuple, Optional

# Suppress only InsecureRequestWarning from urllib3
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class SSLTLSChecker:
    def __init__(self, target, timeout=10, threads=5):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = {
            "target": target,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "vulnerabilities": [],
            "recommendations": []
        }
        
    def parse_target(self):
        """Parse and normalize target URL"""
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        
        parsed = urlparse(self.target)
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
        self.protocol = parsed.scheme
        
    def check_ssl_version(self):
        """Check supported SSL/TLS versions"""
        versions = {
            ssl.PROTOCOL_TLS_CLIENT: {
                'name': 'TLS',
                'versions': []
            }
        }
        
        # Define TLS versions to check
        tls_versions = [
            (ssl.TLSVersion.SSLv3, "SSLv3", True, "CRITICAL"),
            (ssl.TLSVersion.TLSv1, "TLSv1.0", True, "HIGH"),
            (ssl.TLSVersion.TLSv1_1, "TLSv1.1", True, "MEDIUM"),
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2", False, "INFO"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3", False, "INFO"),
        ]
        
        supported = []
        vulnerabilities = []
        
        for tls_version, name, is_vulnerable, severity in tls_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = tls_version
                context.maximum_version = tls_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        supported.append(name)
                        if is_vulnerable:
                            vulnerabilities.append({
                                "version": name,
                                "severity": severity,
                                "message": f"{name} is enabled - vulnerable to known attacks"
                            })
            except (ssl.SSLError, socket.error, Exception):
                pass
        
        finding = {
            "category": "SSL/TLS Versions",
            "supported_versions": supported,
            "severity": "CRITICAL" if any(v in supported for v in ["SSLv3", "TLSv1.0"]) else "MEDIUM" if "TLSv1.1" in supported else "INFO"
        }
        
        if vulnerabilities:
            finding["message"] = "Outdated/deprecated TLS versions detected"
            finding["vulnerabilities"] = vulnerabilities
            self.results["vulnerabilities"].append(finding)
        else:
            finding["message"] = "Only modern TLS versions supported"
            
        self.results["findings"].append(finding)
        
    def check_certificate_info(self):
        """Extract and analyze SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Extract certificate info using UTC methods
                    issuer = cert.issuer.rfc4514_string()
                    subject = cert.subject.rfc4514_string()
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    serial = cert.serial_number
                    
                    # Calculate SHA256 fingerprint
                    fingerprint = hashlib.sha256(cert_bin).hexdigest()
                    
                    # Check expiration
                    now = datetime.now(timezone.utc)
                    days_left = (not_after - now).days
                    
                    # Check if certificate is valid for the hostname
                    try:
                        context.check_hostname = True
                        context.verify_mode = ssl.CERT_REQUIRED
                        with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                                hostname_valid = True
                    except Exception:
                        hostname_valid = False
                    
                    finding = {
                        "category": "Certificate Information",
                        "issuer": issuer,
                        "subject": subject,
                        "valid_from": str(not_before),
                        "valid_until": str(not_after),
                        "days_left": days_left,
                        "hostname_matches": hostname_valid,
                        "fingerprint_sha256": fingerprint,
                        "serial_number": hex(serial),
                        "severity": "CRITICAL" if days_left < 0 else "HIGH" if days_left < 30 else "MEDIUM" if not hostname_valid else "INFO"
                    }
                    
                    if days_left < 0:
                        finding["message"] = "Certificate has EXPIRED!"
                        self.results["vulnerabilities"].append(finding)
                    elif days_left < 30:
                        finding["message"] = f"Certificate expires in {days_left} days"
                        self.results["vulnerabilities"].append(finding)
                    elif not hostname_valid:
                        finding["message"] = "Certificate hostname mismatch!"
                        self.results["vulnerabilities"].append(finding)
                        self.results["recommendations"].append("Fix certificate hostname validation")
                    else:
                        finding["message"] = "Certificate is valid"
                        
                    self.results["findings"].append(finding)
                    
                    # Check for weak signature algorithm
                    sig_algo = cert.signature_algorithm_oid._name
                    weak_algos = ['md5', 'sha1']
                    if any(weak in sig_algo.lower() for weak in weak_algos):
                        weak_finding = {
                            "category": "Weak Signature Algorithm",
                            "algorithm": sig_algo,
                            "message": f"Weak signature algorithm detected: {sig_algo}",
                            "severity": "MEDIUM"
                        }
                        self.results["vulnerabilities"].append(weak_finding)
                        self.results["findings"].append(weak_finding)
                        
        except Exception as e:
            self.results["findings"].append({
                "category": "Certificate Information",
                "error": str(e),
                "severity": "ERROR"
            })
    
    def check_cipher_suites(self):
        """Check for weak cipher suites using ssl module"""
        weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'IDEA', 'SEED',
            'CAMELLIA', 'AES128-SHA', 'AES256-SHA', '3DES'
        ]
        
        try:
            # Use OpenSSL command line if available
            try:
                result = subprocess.run(
                    ['openssl', 's_client', '-connect', f'{self.hostname}:{self.port}', 
                     '-cipher', 'ALL', '-tls1_2'],
                    input='Q\n',
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                weak_found = []
                for line in result.stderr.split('\n'):
                    for weak in weak_ciphers:
                        if weak.lower() in line.lower() and 'Cipher' in line:
                            weak_found.append(line.strip())
                
                if weak_found:
                    finding = {
                        "category": "Cipher Suites",
                        "weak_ciphers_found": weak_found[:10],
                        "message": "Weak cipher suites detected",
                        "severity": "HIGH"
                    }
                    self.results["vulnerabilities"].append(finding)
                    self.results["findings"].append(finding)
                    self.results["recommendations"].append("Disable weak cipher suites (DES, RC4, MD5, 3DES)")
                else:
                    self.results["findings"].append({
                        "category": "Cipher Suites",
                        "message": "No obvious weak cipher suites detected",
                        "severity": "INFO"
                    })
                    
            except FileNotFoundError:
                # Fallback to basic SSL context check
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers('ALL')
                self.results["findings"].append({
                    "category": "Cipher Suites",
                    "message": "OpenSSL not installed - limited cipher check performed",
                    "severity": "INFO"
                })
                
        except Exception as e:
            self.results["findings"].append({
                "category": "Cipher Suites",
                "error": str(e),
                "severity": "ERROR"
            })
    
    def check_hsts(self):
        """Check for HSTS header"""
        try:
            response = requests.get(
                f"{self.protocol}://{self.hostname}",
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            hsts = response.headers.get('Strict-Transport-Security')
            if hsts:
                max_age = re.search(r'max-age=(\d+)', hsts)
                include_subdomains = 'includeSubDomains' in hsts
                preload = 'preload' in hsts
                
                max_age_seconds = int(max_age.group(1)) if max_age else 0
                max_age_days = max_age_seconds / 86400
                
                finding = {
                    "category": "HSTS",
                    "present": True,
                    "max_age_seconds": max_age_seconds,
                    "max_age_days": round(max_age_days, 2),
                    "include_subdomains": include_subdomains,
                    "preload": preload,
                    "severity": "INFO"
                }
                
                if max_age_seconds >= 31536000:
                    finding["message"] = "HSTS properly configured with 1+ year max-age"
                elif max_age_seconds > 0:
                    finding["message"] = f"HSTS max-age is {max_age_days} days (should be at least 365)"
                    self.results["recommendations"].append("Increase HSTS max-age to at least 31536000 seconds (1 year)")
                else:
                    finding["message"] = "HSTS has invalid max-age"
                    self.results["vulnerabilities"].append(finding)
                    
            else:
                finding = {
                    "category": "HSTS",
                    "present": False,
                    "message": "HSTS header not set - vulnerable to SSL stripping attacks",
                    "severity": "MEDIUM"
                }
                self.results["vulnerabilities"].append(finding)
                self.results["recommendations"].append("Implement HSTS header with max-age=31536000; includeSubDomains; preload")
                
            self.results["findings"].append(finding)
            
        except Exception as e:
            self.results["findings"].append({
                "category": "HSTS",
                "error": str(e),
                "severity": "ERROR"
            })
    
    def check_http_security_headers(self):
        """Check for security headers"""
        headers_to_check = {
            'Content-Security-Policy': 'Prevents XSS and data injection attacks',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'Enables browser XSS filtering',
            'Referrer-Policy': 'Controls referrer information leakage',
            'Permissions-Policy': 'Controls browser features/permissions'
        }
        
        try:
            response = requests.get(
                f"{self.protocol}://{self.hostname}",
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            missing_headers = []
            for header, description in headers_to_check.items():
                if header not in response.headers:
                    missing_headers.append({"header": header, "description": description})
                    
            if missing_headers:
                finding = {
                    "category": "Security Headers",
                    "missing_headers": missing_headers,
                    "message": f"Missing {len(missing_headers)} security headers",
                    "severity": "MEDIUM"
                }
                self.results["vulnerabilities"].append(finding)
                for header in missing_headers:
                    self.results["recommendations"].append(f"Add {header['header']} header: {header['description']}")
            else:
                finding = {
                    "category": "Security Headers",
                    "message": "All recommended security headers present",
                    "severity": "INFO"
                }
                
            self.results["findings"].append(finding)
            
        except Exception as e:
            self.results["findings"].append({
                "category": "Security Headers",
                "error": str(e),
                "severity": "ERROR"
            })
    
    def check_tls_compression(self):
        """Check for TLS compression (CRIME vulnerability)"""
        try:
            # Test with openssl if available
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.hostname}:{self.port}', 
                 '-tls1_2', '-tlsextdebug'],
                input='Q\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if 'Compression: NONE' in result.stderr:
                finding = {
                    "category": "TLS Compression",
                    "compression_enabled": False,
                    "message": "TLS compression disabled - not vulnerable to CRIME attack",
                    "severity": "INFO"
                }
            elif 'Compression: 1 (ZLIB)' in result.stderr:
                finding = {
                    "category": "TLS Compression",
                    "compression_enabled": True,
                    "message": "TLS compression enabled - VULNERABLE to CRIME attack (CVE-2012-4929)",
                    "severity": "HIGH"
                }
                self.results["vulnerabilities"].append(finding)
                self.results["recommendations"].append("Disable TLS compression to prevent CRIME attack")
            else:
                finding = {
                    "category": "TLS Compression",
                    "message": "Unable to determine TLS compression status",
                    "severity": "INFO"
                }
                
            self.results["findings"].append(finding)
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.results["findings"].append({
                "category": "TLS Compression",
                "message": "OpenSSL not available - skipping compression check",
                "severity": "INFO"
            })
        except Exception as e:
            self.results["findings"].append({
                "category": "TLS Compression",
                "error": str(e),
                "severity": "ERROR"
            })
    
    def check_certificate_transparency(self):
        """Check for Certificate Transparency information"""
        finding = {
            "category": "Certificate Transparency",
            "message": "Check certificate at https://crt.sh/?q=" + self.hostname,
            "severity": "INFO"
        }
        self.results["findings"].append(finding)
    
    def run_scan(self):
        """Run all checks"""
        self.parse_target()
        print(f"\n[*] Scanning: {self.hostname}:{self.port}")
        print("[*] Starting SSL/TLS security assessment...\n")
        
        checks = [
            self.check_ssl_version,
            self.check_certificate_info,
            self.check_cipher_suites,
            self.check_hsts,
            self.check_http_security_headers,
            self.check_tls_compression,
            self.check_certificate_transparency
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check) for check in checks]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error in check: {e}")
        
        return self.results
    
    def print_results(self):
        """Print formatted results"""
        print("\n" + "="*80)
        print(f"SSL/TLS Security Assessment Report for {self.results['target']}")
        print(f"Scan Time: {self.results['scan_time']}")
        print("="*80)
        
        # Color codes
        RED = '\033[91m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        BLUE = '\033[94m'
        RESET = '\033[0m'
        
        severity_colors = {
            "CRITICAL": RED,
            "HIGH": RED,
            "MEDIUM": YELLOW,
            "INFO": GREEN,
            "ERROR": RED
        }
        
        for finding in self.results['findings']:
            color = severity_colors.get(finding.get('severity', 'INFO'), RESET)
            print(f"\n{color}[+] {finding['category']}{RESET}")
            print("-" * 40)
            for key, value in finding.items():
                if key not in ['category', 'severity']:
                    if isinstance(value, list) and key == 'missing_headers':
                        print(f"  {key}:")
                        for header in value:
                            print(f"    - {header['header']}: {header['description']}")
                    elif isinstance(value, dict):
                        print(f"  {key}:")
                        for subkey, subvalue in value.items():
                            print(f"    {subkey}: {subvalue}")
                    else:
                        print(f"  {key}: {value}")
            print(f"  Severity: {finding.get('severity', 'UNKNOWN')}")
        
        if self.results['vulnerabilities']:
            print(f"\n{RED}{'='*80}{RESET}")
            print(f"{RED}VULNERABILITIES FOUND{RESET}")
            print(f"{RED}{'='*80}{RESET}")
            for vuln in self.results['vulnerabilities']:
                vuln_color = severity_colors.get(vuln.get('severity', 'MEDIUM'), YELLOW)
                print(f"\n{vuln_color}[{vuln.get('severity', 'MEDIUM')}] {vuln['category']}{RESET}")
                print(f"  {vuln.get('message', 'No details')}")
                if 'vulnerabilities' in vuln:
                    for v in vuln['vulnerabilities']:
                        print(f"    - {v.get('version', 'Unknown')}: {v.get('message', '')}")
        
        if self.results['recommendations']:
            print(f"\n{BLUE}{'='*80}{RESET}")
            print(f"{BLUE}RECOMMENDATIONS{RESET}")
            print(f"{BLUE}{'='*80}{RESET}")
            for rec in sorted(set(self.results['recommendations'])):
                print(f"  • {rec}")
        
        print("\n" + "="*80)
        print(f"Total Findings: {len(self.results['findings'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"Recommendations: {len(set(self.results['recommendations']))}")

def main():
    parser = argparse.ArgumentParser(
        description='SSL/TLS Security Assessment Tool for Bug Bounty',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com:8443 -t 30
  %(prog)s example.com -o report.json
  %(prog)s example.com --threads 10
        """
    )
    parser.add_argument('target', help='Target website (e.g., example.com or https://example.com)')
    parser.add_argument('-p', '--port', type=int, help='Port number (overrides URL port)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    # Override port if specified
    if args.port:
        if not args.target.startswith(('http://', 'https://')):
            args.target = f'https://{args.target}:{args.port}'
        else:
            parsed = urlparse(args.target)
            args.target = f"{parsed.scheme}://{parsed.hostname}:{args.port}"
    
    checker = SSLTLSChecker(args.target, args.timeout, args.threads)
    results = checker.run_scan()
    checker.print_results()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[*] Results saved to {args.output}")

if __name__ == "__main__":
    main()
