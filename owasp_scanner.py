#!/usr/bin/env python3
"""
OWASP Top 10 (2021) oriented checks – passive / light active, free only.
Not a full penetration test; maps practical signals to each category.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
TIMEOUT = 10

# category_id -> name (OWASP Top 10 2021)
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}


def _norm(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def _get(url: str, **kw) -> Optional[requests.Response]:
    try:
        return _session().get(url, timeout=TIMEOUT, allow_redirects=True, verify=kw.get("verify", True))
    except requests.exceptions.SSLError:
        try:
            return _session().get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        except Exception:
            return None
    except Exception:
        return None


def _finding(category: str, severity: str, title: str, detail: str) -> Dict[str, Any]:
    return {
        "category": category,
        "category_name": OWASP_CATEGORIES.get(category, category),
        "severity": severity,  # critical|high|medium|low|info|pass
        "title": title,
        "detail": detail,
    }


def check_a01_access_control(base: str) -> List[Dict[str, Any]]:
    """A01: Broken Access Control – exposed admin / sensitive paths."""
    out = []
    paths = [
        ("/admin", "Admin panel path"),
        ("/admin/", "Admin panel path"),
        ("/administrator/", "Joomla-style admin"),
        ("/wp-admin/", "WordPress admin"),
        ("/user/login", "User login"),
        ("/.git/HEAD", "Git metadata"),
        ("/backup.sql", "DB backup"),
        ("/dump.sql", "DB dump"),
        ("/actuator/env", "Spring env endpoint"),
        ("/server-status", "Apache status"),
    ]
    exposed = []
    for path, label in paths:
        try:
            r = _session().get(urljoin(base + "/", path.lstrip("/")), timeout=8, allow_redirects=False, verify=True)
            if r.status_code == 200 and len(r.content) > 50:
                body = (r.text or "")[:800].lower()
                if "not found" in body and "404" in body:
                    continue
                exposed.append(f"{path} ({label})")
        except Exception:
            continue
    if exposed:
        out.append(_finding("A01", "high", "Sensitive or admin paths accessible",
                            "Accessible without strong access control signal: " + ", ".join(exposed[:8])))
    else:
        out.append(_finding("A01", "pass", "No obvious public admin/sensitive paths",
                            "Common admin/backup paths not openly readable (200)."))
    return out


def check_a02_crypto(base: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """A02: Cryptographic Failures – HTTPS, HSTS, cookies."""
    out = []
    parsed = urlparse(base)
    if parsed.scheme != "https":
        out.append(_finding("A02", "critical", "Site not served over HTTPS",
                            "Plain HTTP exposes data in transit."))
    else:
        out.append(_finding("A02", "pass", "HTTPS in use", "Primary URL uses HTTPS."))
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        out.append(_finding("A02", "high", "HSTS header missing",
                            "Browsers may still allow HTTP downgrade on first visit."))
    else:
        out.append(_finding("A02", "pass", "HSTS present", hsts[:100]))
    # cookies
    # checked elsewhere; signal if no secure transport
    return out


def check_a03_injection(base: str) -> List[Dict[str, Any]]:
    """A03: Injection – light reflection / error-based signals only."""
    out = []
    # Reflected XSS-ish probe in query (not exploiting – look for reflection)
    probe = "owaspProbe7x9q"
    try:
        r = _session().get(base + "/", params={"q": probe, "search": probe, "id": probe},
                           timeout=TIMEOUT, allow_redirects=True)
        if r is not None and probe in (r.text or ""):
            out.append(_finding("A03", "medium", "User input reflected in response",
                                "Query parameter value reflected in HTML – review XSS encoding."))
        else:
            out.append(_finding("A03", "info", "No simple reflection on common params",
                                "Checked q/search/id – no obvious unencoded reflection."))
    except Exception:
        out.append(_finding("A03", "info", "Injection probe skipped", "Request failed."))
    # SQL error patterns on id=
    try:
        r = _session().get(base + "/", params={"id": "1'"}, timeout=TIMEOUT, allow_redirects=True)
        text = (r.text or "").lower() if r else ""
        if any(x in text for x in ("sql syntax", "mysql_", "odbc", "sqlite", "postgresql", "ora-")):
            out.append(_finding("A03", "high", "Possible SQL error disclosure",
                                "Database error text appeared after a quote in id parameter."))
    except Exception:
        pass
    return out


def check_a04_insecure_design(base: str) -> List[Dict[str, Any]]:
    """A04: Insecure Design – limited automated signals."""
    return [_finding("A04", "info", "Design review required",
                     "Insecure design needs threat modeling and manual review; not fully automatable.")]


def check_a05_misconfig(base: str, headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
    """A05: Security Misconfiguration – headers, server banner, defaults."""
    out = []
    # Security headers
    needed = {
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    missing = [label for key, label in needed.items() if key not in headers]
    if missing:
        out.append(_finding("A05", "high", "Missing security headers",
                            "Missing: " + ", ".join(missing)))
    else:
        out.append(_finding("A05", "pass", "Core security headers present",
                            "CSP, XCTO, XFO/frame, Referrer-Policy, Permissions-Policy seen."))
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server or powered:
        out.append(_finding("A05", "low", "Server technology disclosure",
                            f"Server={server or '–'} X-Powered-By={powered or '–'}"))
    # Directory listing
    if re.search(r"Index of\s+/", body or "", re.I):
        out.append(_finding("A05", "high", "Directory listing enabled",
                            "Page body looks like an autoindex listing."))
    # TRACE
    try:
        t = _session().request("TRACE", base, timeout=6, allow_redirects=False)
        if t.status_code == 200:
            out.append(_finding("A05", "medium", "HTTP TRACE enabled",
                                "TRACE can assist cross-site tracing attacks."))
    except Exception:
        pass
    return out


def check_a06_components(technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A06: Vulnerable components – relies on detected versions."""
    out = []
    versioned = [t for t in (technologies or []) if t.get("version")]
    if not versioned:
        out.append(_finding("A06", "info", "Few component versions detected",
                            "Run Tech Stack scan; use Vuln Scan for NVD CVE lookup on versions."))
    else:
        names = [f"{t.get('name')} {t.get('version')}" for t in versioned[:10]]
        out.append(_finding("A06", "medium", "Components with visible versions",
                            "Review for outdated software: " + ", ".join(names) +
                            ". Use 🛡 Vuln Scan for NVD CVEs."))
    return out


def check_a07_auth(base: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """A07: Identification & Authentication Failures."""
    out = []
    login_paths = ["/login", "/wp-login.php", "/user/login", "/admin/login", "/account/login"]
    found_login = []
    for path in login_paths:
        try:
            r = _session().get(urljoin(base + "/", path.lstrip("/")), timeout=8, allow_redirects=True, verify=True)
            if r.status_code == 200 and len(r.content) > 200:
                if re.search(r"<form[^>]+", r.text or "", re.I):
                    found_login.append(path)
        except Exception:
            continue
    if found_login:
        out.append(_finding("A07", "info", "Login forms discovered",
                            "Paths: " + ", ".join(found_login) +
                            " – ensure MFA, lockout, and no credential stuffing gaps."))
    else:
        out.append(_finding("A07", "info", "No common login paths found",
                            "Could not confirm login UI on common paths."))
    # Autocomplete on password often not visible without form parse – skip
    return out


def check_a08_integrity(base: str, body: str) -> List[Dict[str, Any]]:
    """A08: Software and Data Integrity – SRI, exposed manifests."""
    out = []
    # External scripts without integrity=
    scripts = re.findall(r"<script[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", body or "", re.I)
    no_sri = []
    for src in scripts[:30]:
        # find tag again roughly
        if "integrity=" not in body[max(0, body.find(src) - 80):body.find(src) + len(src) + 40]:
            if urlparse(src).netloc and urlparse(src).netloc not in urlparse(base).netloc:
                no_sri.append(src[:80])
    if no_sri:
        out.append(_finding("A08", "medium", "Third-party scripts without SRI",
                            f"{len(no_sri)} external script(s) without Subresource Integrity, e.g. {no_sri[0]}"))
    else:
        out.append(_finding("A08", "pass", "No obvious third-party scripts missing SRI",
                            "Either no external scripts or integrity attributes present."))
    for path in ("/package.json", "/composer.json", "/.git/HEAD"):
        try:
            r = _session().get(urljoin(base + "/", path.lstrip("/")), timeout=6, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 20:
                out.append(_finding("A08", "high", f"Exposed {path}",
                                    "Source integrity / supply-chain risk if public."))
        except Exception:
            pass
    return out


def check_a09_logging(base: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """A09: Security Logging & Monitoring – weak automated signals."""
    out = []
    # security.txt
    st = None
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = _session().get(urljoin(base + "/", path.lstrip("/")), timeout=6, allow_redirects=True)
            if r.status_code == 200 and "contact:" in (r.text or "").lower():
                st = path
                break
        except Exception:
            pass
    if st:
        out.append(_finding("A09", "pass", "security.txt found", f"Present at {st}"))
    else:
        out.append(_finding("A09", "low", "No security.txt",
                            "Consider RFC 9116 security.txt for vulnerability reporting."))
    # CSP report-only / report-to as monitoring signal
    if headers.get("content-security-policy-report-only") or "report-to" in headers.get("content-security-policy", "").lower():
        out.append(_finding("A09", "pass", "CSP reporting configured",
                            "CSP report-only or report-to directive present."))
    else:
        out.append(_finding("A09", "info", "No CSP reporting observed",
                            "CSP report-to / report-uri helps detect XSS attempts."))
    return out


def check_a10_ssrf(base: str) -> List[Dict[str, Any]]:
    """A10: SSRF – open redirect style params only (safe)."""
    out = []
    # Open redirect probe – if Location reflects external URL
    targets = [
        ("url", "https://example.com/"),
        ("next", "https://example.com/"),
        ("redirect", "https://example.com/"),
        ("returnUrl", "https://example.com/"),
        ("goto", "https://example.com/"),
    ]
    risky = []
    for param, val in targets:
        try:
            r = _session().get(base + "/", params={param: val}, timeout=8, allow_redirects=False)
            loc = r.headers.get("Location", "") if r is not None else ""
            if "example.com" in loc:
                risky.append(param)
        except Exception:
            continue
    if risky:
        out.append(_finding("A10", "high", "Possible open redirect",
                            "Redirect parameters reflected external URL: " + ", ".join(risky) +
                            " (related to SSRF/redirect abuse chains)."))
    else:
        out.append(_finding("A10", "info", "No open redirect on common params",
                            "Checked url/next/redirect/returnUrl/goto – no external Location."))
    out.append(_finding("A10", "info", "Full SSRF needs manual testing",
                        "Blind SSRF requires out-of-band channels; not performed automatically."))
    return out


def run_owasp_scan(url: str, technologies: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Run OWASP Top 10 oriented checks against one URL.
    Returns structured findings per category + scorecard.
    """
    url = _norm(url)
    result: Dict[str, Any] = {
        "url": url,
        "findings": [],
        "by_category": {},
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "pass": 0},
        "error": None,
    }
    if not url:
        result["error"] = "Empty URL"
        return result

    resp = _get(url)
    if resp is None:
        result["error"] = "Could not fetch URL"
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    try:
        body = resp.text[:400000]
    except Exception:
        body = ""

    techs = technologies or []

    all_findings: List[Dict[str, Any]] = []
    all_findings.extend(check_a01_access_control(url))
    all_findings.extend(check_a02_crypto(url, headers))
    all_findings.extend(check_a03_injection(url))
    all_findings.extend(check_a04_insecure_design(url))
    all_findings.extend(check_a05_misconfig(url, headers, body))
    all_findings.extend(check_a06_components(techs))
    all_findings.extend(check_a07_auth(url, headers))
    all_findings.extend(check_a08_integrity(url, body))
    all_findings.extend(check_a09_logging(url, headers))
    all_findings.extend(check_a10_ssrf(url))

    result["findings"] = all_findings
    for f in all_findings:
        cat = f["category"]
        result["by_category"].setdefault(cat, []).append(f)
        sev = f.get("severity", "info")
        if sev in result["summary"]:
            result["summary"][sev] += 1

    # Simple risk score 0-100 (higher = worse)
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0, "pass": 0}
    risk = sum(weights.get(f.get("severity", "info"), 0) for f in all_findings)
    result["risk_score"] = min(100, risk)
    if risk >= 50:
        result["risk_label"] = "High"
    elif risk >= 25:
        result["risk_label"] = "Medium"
    elif risk >= 10:
        result["risk_label"] = "Low"
    else:
        result["risk_label"] = "Good"

    return result
