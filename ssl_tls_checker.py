#!/usr/bin/env python3
"""
SSL/TLS Security Checker for Bug Bounty
Author: Bug Bounty Tool
Description: Comprehensive SSL/TLS analysis tool for security researchers
"""

import ssl
import socket
import sys
import json
import datetime
import argparse
import concurrent.futures
from urllib.parse import urlparse


# ─────────────────────────────────────────────
#  ANSI Colors
# ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║         SSL/TLS Bug Bounty Checker v1.0              ║
║         For Security Research & Bug Bounty           ║
╚══════════════════════════════════════════════════════╝
{RESET}"""

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def clean_host(target: str) -> tuple[str, int]:
    """Extract hostname and port from a raw target string."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or 443
    return host, port


def tag(ok: bool) -> str:
    return f"{GREEN}[✔ PASS]{RESET}" if ok else f"{RED}[✘ FAIL]{RESET}"


def info(label: str, value: str, warn: bool = False) -> None:
    color = YELLOW if warn else CYAN
    print(f"  {color}{label:<35}{RESET} {value}")


# ─────────────────────────────────────────────
#  Core checks
# ─────────────────────────────────────────────

def get_cert(host: str, port: int, tls_version=None) -> dict | None:
    """Retrieve the certificate from the server."""
    ctx = ssl.create_default_context()
    if tls_version:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "tls_version": version}
    except Exception:
        return None


def check_cert_expiry(cert: dict) -> dict:
    """Check if the certificate is expired or expiring soon."""
    not_after = cert.get("notAfter", "")
    expire_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    now = datetime.datetime.utcnow()
    days_left = (expire_dt - now).days
    expired = days_left < 0
    expiring_soon = 0 <= days_left <= 30
    return {
        "expiry_date": not_after,
        "days_remaining": days_left,
        "expired": expired,
        "expiring_soon": expiring_soon,
    }


def check_self_signed(cert: dict) -> bool:
    """Return True if the certificate is self-signed."""
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    return issuer == subject


def check_hostname_mismatch(cert: dict, host: str) -> bool:
    """Return True if hostname matches the cert (no mismatch). Compatible with Python 3.12+."""
    import fnmatch

    # Collect all valid names from SAN + CN fallback
    names = []
    for entry in cert.get("subjectAltName", []):
        if entry[0].lower() == "dns":
            names.append(entry[1].lower())

    # Fallback to CN if no SANs
    if not names:
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        if cn:
            names.append(cn.lower())

    host_lower = host.lower()
    for name in names:
        if fnmatch.fnmatch(host_lower, name):
            return True
    return False


def check_weak_signature(cert: dict) -> bool:
    """Return True if a weak signature algorithm is detected."""
    sig_alg = cert.get("signatureAlgorithm", "").lower()
    weak = ["md5", "sha1", "md2"]
    return any(w in sig_alg for w in weak)


def check_san(cert: dict) -> list:
    """Extract Subject Alternative Names."""
    san = []
    for entry in cert.get("subjectAltName", []):
        san.append(f"{entry[0]}:{entry[1]}")
    return san


def probe_tls_versions(host: str, port: int) -> dict:
    """Probe which TLS/SSL versions the server accepts."""
    versions = {
        "SSLv3":   None,
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    results = {}
    for name, ver in versions.items():
        if name == "SSLv3":
            # SSLv3 is removed from Python's ssl; always mark as not supported
            results[name] = False
            continue
        data = get_cert(host, port, tls_version=ver)
        results[name] = data is not None
    return results


def check_hsts(host: str, port: int) -> bool:
    """Check for Strict-Transport-Security header (basic TCP read)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode())
                response = b""
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
        return b"strict-transport-security" in response.lower()
    except Exception:
        return False


def check_cipher_strength(cipher_name: str) -> str:
    """Classify cipher strength."""
    cipher_lower = cipher_name.lower()
    weak_ciphers = ["rc4", "des", "3des", "export", "null", "anon", "rc2"]
    if any(w in cipher_lower for w in weak_ciphers):
        return "WEAK"
    if "aes_128" in cipher_lower or "chacha20" in cipher_lower or "aes_256" in cipher_lower:
        return "STRONG"
    return "MEDIUM"


def check_cert_transparency(cert: dict) -> bool:
    """Check for Certificate Transparency extension (basic check)."""
    extensions = cert.get("extensions", {})
    # In Python ssl, CT is not directly exposed; flag as unknown
    return None  # Cannot reliably check via stdlib


# ─────────────────────────────────────────────
#  Report
# ─────────────────────────────────────────────

def run_checks(host: str, port: int, json_out: bool = False) -> dict:
    print(f"\n{BOLD}[*] Target: {CYAN}{host}:{port}{RESET}")
    print("─" * 60)

    # Grab certificate
    print(f"{BOLD}[1] Connecting & fetching certificate...{RESET}")
    conn = get_cert(host, port)
    if not conn:
        msg = f"{RED}Could not connect or retrieve certificate.{RESET}"
        print(msg)
        return {"error": "Connection failed"}

    cert        = conn["cert"]
    cipher      = conn["cipher"]       # (name, protocol, bits)
    tls_version = conn["tls_version"]

    result = {}

    # ── Certificate Info ──
    print(f"\n{BOLD}[2] Certificate Details{RESET}")
    subject   = dict(x[0] for x in cert.get("subject", []))
    issuer    = dict(x[0] for x in cert.get("issuer", []))
    cn        = subject.get("commonName", "N/A")
    org       = subject.get("organizationName", "N/A")
    issuer_cn = issuer.get("commonName", "N/A")
    serial    = cert.get("serialNumber", "N/A")
    sig_alg   = cert.get("signatureAlgorithm", "N/A")

    info("Common Name (CN):", cn)
    info("Organization:", org)
    info("Issuer:", issuer_cn)
    info("Serial Number:", serial)
    info("Signature Algorithm:", sig_alg, warn="sha1" in sig_alg.lower() or "md5" in sig_alg.lower())
    result["subject_cn"]        = cn
    result["issuer"]            = issuer_cn
    result["signature_algorithm"] = sig_alg

    # ── Expiry ──
    print(f"\n{BOLD}[3] Certificate Expiry{RESET}")
    expiry = check_cert_expiry(cert)
    status = "EXPIRED" if expiry["expired"] else ("EXPIRING SOON" if expiry["expiring_soon"] else "VALID")
    color  = RED if expiry["expired"] else (YELLOW if expiry["expiring_soon"] else GREEN)
    info("Expiry Date:", expiry["expiry_date"])
    info("Days Remaining:", f"{color}{expiry['days_remaining']} days  [{status}]{RESET}")
    result["expiry"] = expiry

    # ── Hostname Match ──
    print(f"\n{BOLD}[4] Hostname Verification{RESET}")
    hostname_ok = check_hostname_mismatch(cert, host)
    print(f"  {tag(hostname_ok)}  Hostname matches certificate")
    result["hostname_match"] = hostname_ok

    # ── Self-signed ──
    print(f"\n{BOLD}[5] Self-Signed Check{RESET}")
    self_signed = check_self_signed(cert)
    print(f"  {tag(not self_signed)}  Certificate is {'SELF-SIGNED ' + RED + '(Bug!)' + RESET if self_signed else 'CA-signed'}")
    result["self_signed"] = self_signed

    # ── Weak Signature ──
    print(f"\n{BOLD}[6] Weak Signature Algorithm{RESET}")
    weak_sig = check_weak_signature(cert)
    print(f"  {tag(not weak_sig)}  {'Weak algorithm detected: ' + RED + sig_alg + RESET if weak_sig else 'Strong signature algorithm'}")
    result["weak_signature"] = weak_sig

    # ── SAN ──
    print(f"\n{BOLD}[7] Subject Alternative Names (SANs){RESET}")
    sans = check_san(cert)
    if sans:
        for s in sans:
            info("  SAN:", s)
    else:
        print(f"  {YELLOW}No SANs found (may be a finding){RESET}")
    result["sans"] = sans

    # ── TLS Versions ──
    print(f"\n{BOLD}[8] TLS/SSL Protocol Support{RESET}")
    print(f"  {YELLOW}(Probing each version — may take a moment...){RESET}")
    tls_results = probe_tls_versions(host, port)
    vulnerable_versions = []
    for ver, supported in tls_results.items():
        is_weak = ver in ("SSLv3", "TLSv1.0", "TLSv1.1")
        if supported and is_weak:
            vulnerable_versions.append(ver)
        label = f"{RED}SUPPORTED (VULNERABLE!){RESET}" if (supported and is_weak) \
            else (f"{GREEN}Supported{RESET}" if supported else f"Not supported")
        print(f"  {'⚠ ' if supported and is_weak else '  '}{ver:<10} {label}")
    result["tls_versions"]       = tls_results
    result["vulnerable_versions"] = vulnerable_versions

    # ── Current Cipher ──
    print(f"\n{BOLD}[9] Active Cipher Suite{RESET}")
    cipher_name = cipher[0] if cipher else "Unknown"
    cipher_bits = cipher[2] if cipher else 0
    strength    = check_cipher_strength(cipher_name)
    strength_color = GREEN if strength == "STRONG" else (YELLOW if strength == "MEDIUM" else RED)
    info("Cipher:", cipher_name)
    info("Key Bits:", str(cipher_bits))
    info("Strength:", f"{strength_color}{strength}{RESET}")
    info("Negotiated TLS:", tls_version or "Unknown")
    result["cipher"] = {"name": cipher_name, "bits": cipher_bits, "strength": strength, "tls": tls_version}

    # ── HSTS ──
    print(f"\n{BOLD}[10] HTTP Strict Transport Security (HSTS){RESET}")
    hsts = check_hsts(host, port)
    print(f"  {tag(hsts)}  HSTS header {'present' if hsts else 'MISSING (potential finding)'}")
    result["hsts"] = hsts

    # ── Summary ──
    print(f"\n{'═'*60}")
    print(f"{BOLD}  SUMMARY / BUG BOUNTY FINDINGS{RESET}")
    print(f"{'═'*60}")
    findings = []

    if expiry["expired"]:
        findings.append(f"{RED}[CRITICAL] Certificate is EXPIRED{RESET}")
    if expiry["expiring_soon"]:
        findings.append(f"{YELLOW}[MEDIUM]   Certificate expiring in {expiry['days_remaining']} days{RESET}")
    if self_signed:
        findings.append(f"{RED}[HIGH]     Self-signed certificate{RESET}")
    if not hostname_ok:
        findings.append(f"{RED}[HIGH]     Hostname mismatch{RESET}")
    if weak_sig:
        findings.append(f"{YELLOW}[MEDIUM]   Weak signature algorithm: {sig_alg}{RESET}")
    if vulnerable_versions:
        for v in vulnerable_versions:
            findings.append(f"{RED}[HIGH]     Deprecated TLS version supported: {v}{RESET}")
    if not hsts:
        findings.append(f"{YELLOW}[MEDIUM]   HSTS header missing{RESET}")
    if strength == "WEAK":
        findings.append(f"{RED}[HIGH]     Weak cipher in use: {cipher_name}{RESET}")
    if not sans:
        findings.append(f"{YELLOW}[LOW]      No SANs present{RESET}")

    if findings:
        for f in findings:
            print(f"  {f}")
    else:
        print(f"  {GREEN}No critical issues detected.{RESET}")

    print(f"{'═'*60}\n")
    result["findings"] = [f.replace("\033[91m","").replace("\033[92m","").replace("\033[93m","").replace("\033[0m","") for f in findings]

    if json_out:
        print(json.dumps(result, indent=2, default=str))

    return result


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="SSL/TLS Security Checker for Bug Bounty",
        epilog="Examples:\n  python3 ssl_tls_checker.py example.com\n  python3 ssl_tls_checker.py example.com:8443 --json",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", help="Target host(s), e.g. example.com or example.com:8443")
    parser.add_argument("--json", action="store_true", help="Also print JSON output")
    parser.add_argument("--threads", type=int, default=1, help="Parallel threads for multiple targets")
    args = parser.parse_args()

    def run(target):
        host, port = clean_host(target)
        run_checks(host, port, json_out=args.json)

    if len(args.targets) == 1 or args.threads == 1:
        for t in args.targets:
            run(t)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            ex.map(run, args.targets)


if __name__ == "__main__":
    main()
