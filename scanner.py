#!/usr/bin/env python3
"""
Security Header Vulnerability Scanner
Scans domains for CSP, HSTS, and other critical security headers.
Generates detailed PDF reports. Designed to run as a scheduled .exe (Windows).
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

# Pakistan Standard Time (UTC+5, no DST)
PKT = timezone(timedelta(hours=5), name="PKT")

def now_pkt() -> datetime:
    return datetime.now(PKT)

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)

# ---------------------------------------------------------------------------
# Configuration / Constants
# ---------------------------------------------------------------------------

DEFAULT_DOMAINS_FILE = "domains.txt"
DEFAULT_OUTPUT_DIR = "reports"
REQUEST_TIMEOUT = 15
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 SecurityHeaderScanner/1.0"
)

# Headers we evaluate (name -> severity if missing/misconfigured)
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "High",
        "description": "Enforces HTTPS-only connections and protects against SSL-stripping / MITM.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": "Critical",
        "description": "Primary defense against XSS and injection attacks by controlling resource origins.",
        "recommended": "default-src 'self'; ... (strict policy without unsafe-inline/eval)",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "Medium",
        "description": "Prevents MIME-type sniffing attacks.",
        "recommended": "nosniff",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "Medium",
        "description": "Protects against clickjacking. Prefer CSP frame-ancestors when possible.",
        "recommended": "DENY or SAMEORIGIN",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "Low",
        "description": "Controls how much referrer information is sent with requests.",
        "recommended": "strict-origin-when-cross-origin or no-referrer",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "Medium",
        "description": "Restricts access to powerful browser features (camera, mic, geolocation, etc.).",
        "recommended": "camera=(), microphone=(), geolocation=(), payment=()",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "severity": "Low",
        "description": "Isolates browsing context to mitigate Spectre-like attacks.",
        "recommended": "same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "severity": "Low",
        "description": "Controls which origins can load the resource.",
        "recommended": "same-origin or same-site",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy (COEP)",
        "severity": "Low",
        "description": "Required for certain advanced features; enables cross-origin isolation.",
        "recommended": "require-corp (when needed)",
    },
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def normalize_url(domain: str) -> str:
    domain = domain.strip()
    if not domain:
        return ""
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    return domain.rstrip("/")


def fetch_headers(url: str) -> Tuple[Optional[Dict[str, str]], Optional[str], int]:
    """Fetch response headers. Returns (headers_dict, final_url, status_code) or error."""
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        # Prefer HEAD, fall back to GET if needed
        resp = session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
        if resp.status_code >= 400 or not resp.headers:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True, stream=True)
            # Don't download body
            resp.close()
        # Normalize header keys to lowercase
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return headers, resp.url, resp.status_code
    except requests.exceptions.SSLError as e:
        return None, None, -1  # special code for SSL
    except requests.exceptions.RequestException as e:
        return None, str(e), 0


def evaluate_hsts(value: Optional[str]) -> Dict[str, Any]:
    result = {
        "present": bool(value),
        "value": value or "",
        "issues": [],
        "score": 0,
        "details": {},
    }
    if not value:
        result["issues"].append("Header is missing")
        return result

    result["score"] = 40
    parts = [p.strip().lower() for p in value.split(";")]
    max_age = None
    has_include = False
    has_preload = False

    for p in parts:
        if p.startswith("max-age="):
            try:
                max_age = int(p.split("=", 1)[1])
            except ValueError:
                result["issues"].append("Invalid max-age value")
        elif p == "includesubdomains":
            has_include = True
        elif p == "preload":
            has_preload = True

    result["details"] = {
        "max_age": max_age,
        "includeSubDomains": has_include,
        "preload": has_preload,
    }

    if max_age is None:
        result["issues"].append("max-age directive missing")
    elif max_age < 31536000:
        result["issues"].append(f"max-age too short ({max_age}s). Recommend >= 31536000 (1 year)")
        result["score"] += 20
    else:
        result["score"] += 30

    if has_include:
        result["score"] += 15
    else:
        result["issues"].append("includeSubDomains missing (recommended)")

    if has_preload:
        result["score"] += 15
    else:
        result["issues"].append("preload missing (recommended for HSTS preload list)")

    result["score"] = min(100, result["score"])
    return result


def evaluate_csp(value: Optional[str]) -> Dict[str, Any]:
    result = {
        "present": bool(value),
        "value": value or "",
        "issues": [],
        "score": 0,
        "details": {},
    }
    if not value:
        result["issues"].append("Header is missing – critical for XSS protection")
        return result

    result["score"] = 50
    lower = value.lower()

    # Dangerous directives / values
    if "'unsafe-inline'" in lower and "script-src" in lower:
        result["issues"].append("Contains 'unsafe-inline' in script-src (weakens XSS protection)")
        result["score"] -= 25
    if "'unsafe-eval'" in lower:
        result["issues"].append("Contains 'unsafe-eval' (allows eval() – dangerous)")
        result["score"] -= 20
    if "*" in lower and ("script-src" in lower or "default-src" in lower):
        result["issues"].append("Wildcard (*) in script-src or default-src is overly permissive")
        result["score"] -= 20

    # Positive signals
    if "default-src" in lower:
        result["score"] += 10
    if "frame-ancestors" in lower:
        result["score"] += 10
        if "frame-ancestors 'none'" in lower or "frame-ancestors 'self'" in lower:
            result["score"] += 5
    if "object-src 'none'" in lower or "object-src 'none'" in lower:
        result["score"] += 5
    if "base-uri" in lower:
        result["score"] += 5
    if "upgrade-insecure-requests" in lower:
        result["score"] += 5

    # Report-only is better than nothing but not enforcement
    # (we check both headers separately)

    result["score"] = max(0, min(100, result["score"]))
    if not result["issues"]:
        result["issues"].append("Present – review policy strength manually (use Google CSP Evaluator)")
    return result


def evaluate_simple(header_key: str, value: Optional[str], expected_values: List[str] = None) -> Dict[str, Any]:
    result = {
        "present": bool(value),
        "value": value or "",
        "issues": [],
        "score": 0,
    }
    if not value:
        result["issues"].append("Header is missing")
        return result

    result["score"] = 70
    lower = value.lower().strip()
    if expected_values:
        if any(ev.lower() in lower for ev in expected_values):
            result["score"] = 100
        else:
            result["issues"].append(f"Value '{value}' is not ideal. Recommended: {', '.join(expected_values)}")
            result["score"] = 50
    else:
        result["score"] = 100
    return result


def scan_domain(domain: str) -> Dict[str, Any]:
    url = normalize_url(domain)
    if not url:
        return {"domain": domain, "error": "Invalid domain", "score": 0}

    headers, final_url, status = fetch_headers(url)

    result = {
        "domain": domain,
        "url": url,
        "final_url": final_url,
        "status_code": status,
        "timestamp": now_pkt().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "headers_found": {},
        "evaluations": {},
        "info_leaks": {},
        "overall_score": 0,
        "grade": "F",
        "error": None,
    }

    if headers is None:
        if status == -1:
            result["error"] = "SSL/TLS certificate error"
        else:
            result["error"] = f"Request failed: {final_url}"
        return result

    # Collect all interesting headers
    for h in list(SECURITY_HEADERS.keys()) + INFO_LEAK_HEADERS + ["content-security-policy-report-only"]:
        if h in headers:
            result["headers_found"][h] = headers[h]

    # Evaluate each
    evals = {}

    # HSTS
    evals["strict-transport-security"] = evaluate_hsts(headers.get("strict-transport-security"))

    # CSP (prefer enforcement over report-only)
    csp_val = headers.get("content-security-policy")
    csp_ro = headers.get("content-security-policy-report-only")
    if csp_val:
        evals["content-security-policy"] = evaluate_csp(csp_val)
    elif csp_ro:
        evals["content-security-policy"] = evaluate_csp(csp_ro)
        evals["content-security-policy"]["issues"].insert(0, "Only Report-Only mode is present (not enforcing)")
        evals["content-security-policy"]["score"] = max(0, evals["content-security-policy"]["score"] - 30)
    else:
        evals["content-security-policy"] = evaluate_csp(None)

    # X-Content-Type-Options
    evals["x-content-type-options"] = evaluate_simple(
        "x-content-type-options", headers.get("x-content-type-options"), ["nosniff"]
    )

    # X-Frame-Options (or note if CSP frame-ancestors covers it)
    xfo = headers.get("x-frame-options")
    evals["x-frame-options"] = evaluate_simple(
        "x-frame-options", xfo, ["DENY", "SAMEORIGIN"]
    )
    if not xfo and "frame-ancestors" in (csp_val or csp_ro or "").lower():
        evals["x-frame-options"]["issues"] = ["Missing, but CSP frame-ancestors is present (acceptable)"]
        evals["x-frame-options"]["score"] = 80
        evals["x-frame-options"]["present"] = True  # treat as covered

    # Referrer-Policy
    evals["referrer-policy"] = evaluate_simple(
        "referrer-policy",
        headers.get("referrer-policy"),
        ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"],
    )

    # Permissions-Policy
    evals["permissions-policy"] = evaluate_simple(
        "permissions-policy", headers.get("permissions-policy")
    )
    if evals["permissions-policy"]["present"]:
        # Bonus if restrictive
        val = headers.get("permissions-policy", "").lower()
        if "camera=()" in val or "microphone=()" in val:
            evals["permissions-policy"]["score"] = min(100, evals["permissions-policy"]["score"] + 20)

    # Modern COOP / CORP / COEP
    for h in ["cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy"]:
        evals[h] = evaluate_simple(h, headers.get(h))

    result["evaluations"] = evals

    # Info leak headers
    for h in INFO_LEAK_HEADERS:
        if h in headers:
            result["info_leaks"][h] = headers[h]

    # Overall score (weighted)
    weights = {
        "strict-transport-security": 0.25,
        "content-security-policy": 0.30,
        "x-content-type-options": 0.10,
        "x-frame-options": 0.10,
        "referrer-policy": 0.08,
        "permissions-policy": 0.07,
        "cross-origin-opener-policy": 0.04,
        "cross-origin-resource-policy": 0.03,
        "cross-origin-embedder-policy": 0.03,
    }
    total = 0.0
    for k, w in weights.items():
        total += evals.get(k, {}).get("score", 0) * w

    # Penalty for info leaks
    if result["info_leaks"]:
        total = max(0, total - 5 * len(result["info_leaks"]))

    result["overall_score"] = round(total, 1)

    # Grade (headers-only until full rating applied)
    s = result["overall_score"]
    if s >= 90:
        result["grade"] = "A+"
    elif s >= 80:
        result["grade"] = "A"
    elif s >= 70:
        result["grade"] = "B"
    elif s >= 60:
        result["grade"] = "C"
    elif s >= 50:
        result["grade"] = "D"
    else:
        result["grade"] = "F"

    # Placeholder full rating (updated after vuln/OWASP)
    result["security_score"] = result["overall_score"]
    result["security_rating"] = result["grade"]
    return result


def score_to_rating(score: float) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def compute_security_rating(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combined security rating from:
      - HTTP security headers (40%)
      - Vulnerability findings (35%)
      - OWASP Top 10 assessment (25%)
    """
    header_score = float(result.get("overall_score") or 0)

    # Vuln component: start 100, subtract by severity counts
    vuln = result.get("vuln") or {}
    vs = vuln.get("summary") or {}
    vuln_score = 100.0
    vuln_score -= 22 * int(vs.get("critical") or 0)
    vuln_score -= 14 * int(vs.get("high") or 0)
    vuln_score -= 7 * int(vs.get("medium") or 0)
    vuln_score -= 3 * int(vs.get("low") or 0)
    # Cap path-based damage slightly if only info findings
    vuln_score = max(0.0, min(100.0, vuln_score))

    # OWASP: invert risk_score (0 good → 100, 100 bad → 0)
    owasp = result.get("owasp") or {}
    if owasp.get("risk_score") is not None:
        owasp_score = max(0.0, min(100.0, 100.0 - float(owasp.get("risk_score") or 0)))
    else:
        owasp_score = header_score  # neutral if missing

    combined = header_score * 0.40 + vuln_score * 0.35 + owasp_score * 0.25
    combined = round(max(0.0, min(100.0, combined)), 1)
    rating = score_to_rating(combined)

    result["security_score"] = combined
    result["security_rating"] = rating
    result["rating_breakdown"] = {
        "headers": round(header_score, 1),
        "vuln": round(vuln_score, 1),
        "owasp": round(owasp_score, 1),
        "weights": {"headers": 0.40, "vuln": 0.35, "owasp": 0.25},
    }
    return result


# ---------------------------------------------------------------------------
# PDF Report Generation
# ---------------------------------------------------------------------------

def get_grade_color(grade: str):
    return {
        "A+": colors.HexColor("#1B5E20"),
        "A": colors.HexColor("#2E7D32"),
        "B": colors.HexColor("#558B2F"),
        "C": colors.HexColor("#F9A825"),
        "D": colors.HexColor("#EF6C00"),
        "F": colors.HexColor("#C62828"),
    }.get(grade, colors.black)




def generate_pdf(results: List[Dict], output_path: str, scan_time: datetime):
    """Clean report with executive summary + full tables for every scan type."""
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=14 * mm, leftMargin=14 * mm,
        topMargin=12 * mm, bottomMargin=12 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="MainTitle", fontSize=16, leading=20, alignment=TA_CENTER,
                              spaceAfter=4, textColor=colors.HexColor("#0E7490"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="SubTitle", fontSize=9, leading=12, alignment=TA_CENTER,
                              spaceAfter=8, textColor=colors.HexColor("#546E7A")))
    styles.add(ParagraphStyle(name="Section", fontSize=12, leading=15, spaceBefore=10, spaceAfter=5,
                              textColor=colors.HexColor("#1565C0"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="DomainTitle", fontSize=11, leading=14, spaceBefore=8, spaceAfter=3,
                              textColor=colors.HexColor("#0D47A1"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="SubHead", fontSize=9, leading=11, spaceBefore=6, spaceAfter=3,
                              textColor=colors.HexColor("#37474F"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="BodySmall", fontSize=8, leading=10, textColor=colors.HexColor("#424242")))
    styles.add(ParagraphStyle(name="Issue", fontSize=8, leading=10, textColor=colors.HexColor("#B71C1C")))
    styles.add(ParagraphStyle(name="Muted", fontSize=7, leading=9, textColor=colors.HexColor("#607D8B")))
    styles.add(ParagraphStyle(name="Footer", fontSize=7, leading=9, alignment=TA_CENTER, textColor=colors.gray))

    def _table(data, col_widths, header_bg="#1565C0"):
        tbl = Table(data, colWidths=col_widths, repeatRows=1)
        cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B0BEC5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
        ]
        tbl.setStyle(TableStyle(cmds))
        return tbl

    story = []
    # Brand header
    story.append(Paragraph("PULSESCAN", styles["MainTitle"]))
    story.append(Paragraph("Security Assessment Report  ·  SYS.VER 4.0.2", styles["SubTitle"]))
    story.append(Paragraph(
        f"Generated: {scan_time.strftime('%Y-%m-%d %H:%M:%S PKT')}  ·  "
        f"Targets: {len(results)}  ·  Modules: Headers · Tech Stack · Vuln · OWASP Top 10",
        styles["SubTitle"],
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#00B8D4"), spaceAfter=4))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#7C3AED"), spaceAfter=8))

    # ========== 1. Executive Summary ==========
    story.append(Paragraph("1. Executive Summary — Combined Security Ratings", styles["Section"]))
    story.append(Paragraph(
        "Overall rating combines HTTP security headers (40%), vulnerability findings (35%), and OWASP Top 10 assessment (25%).",
        styles["Muted"],
    ))
    summary_data = [["Domain", "Rating", "Score", "Headers", "Vuln", "OWASP"]]
    rating_counts = {}
    for r in results:
        if r.get("error"):
            summary_data.append([str(r.get("domain", "?"))[:42], "ERR", "–", "–", "–", "–"])
            continue
        br = r.get("rating_breakdown") or {}
        rating = r.get("security_rating") or r.get("grade") or "F"
        rating_counts[rating] = rating_counts.get(rating, 0) + 1
        summary_data.append([
            str(r.get("domain", "?"))[:42],
            str(rating),
            str(r.get("security_score", r.get("overall_score", "–"))),
            str(br.get("headers", r.get("overall_score", "–"))),
            str(br.get("vuln", "–")),
            str(br.get("owasp", "–")),
        ])

    st = _table(summary_data, [52*mm, 16*mm, 16*mm, 20*mm, 20*mm, 20*mm])
    # Color rating column
    extra = []
    rcmap = {
        "A+": "#C8E6C9", "A": "#C8E6C9", "B": "#DCEDC8",
        "C": "#FFF9C4", "D": "#FFE0B2", "F": "#FFCDD2", "ERR": "#EF9A9A",
    }
    for i, row in enumerate(summary_data[1:], start=1):
        bg = rcmap.get(str(row[1]), "#FFFFFF")
        extra.append(("BACKGROUND", (1, i), (1, i), colors.HexColor(bg)))
        extra.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
    st.setStyle(TableStyle(extra))
    story.append(st)
    story.append(Paragraph(
        "Combined score = Headers 40% + Vuln 35% + OWASP T10 25%.  "
        + ("Distribution: " + "  ".join(f"{k}={v}" for k, v in sorted(rating_counts.items())) if rating_counts else ""),
        styles["Muted"],
    ))

    # ========== 2. Per-domain full tables ==========
    story.append(Paragraph("2. Detailed Findings by Domain", styles["Section"]))

    for r in results:
        domain = r.get("domain", "unknown")
        if r.get("error"):
            story.append(Paragraph(f"{domain} — Error: {r.get('error')}", styles["Issue"]))
            story.append(Spacer(1, 4))
            continue

        rating = r.get("security_rating") or r.get("grade") or "F"
        score = r.get("security_score", r.get("overall_score", 0))
        br = r.get("rating_breakdown") or {}
        story.append(Paragraph(
            f"{domain}  —  Security Rating <b>{rating}</b> ({score}/100)",
            styles["DomainTitle"],
        ))
        story.append(Paragraph(
            f"Breakdown: headers={br.get('headers', '–')} · vuln={br.get('vuln', '–')} · "
            f"OWASP={br.get('owasp', '–')}  |  HTTP {r.get('status_code', '–')}  |  {r.get('final_url') or ''}",
            styles["Muted"],
        ))

        # --- Headers table ---
        story.append(Paragraph("Security Headers", styles["SubHead"]))
        hrows = [["Header", "Status", "Score", "Notes"]]
        for key, meta in SECURITY_HEADERS.items():
            ev = (r.get("evaluations") or {}).get(key, {})
            status = "Present" if ev.get("present") else "Missing"
            if ev.get("present") and ev.get("score", 0) < 60:
                status = "Weak"
            notes = "; ".join(ev.get("issues") or []) or (ev.get("value") or "—")
            if len(str(notes)) > 90:
                notes = str(notes)[:87] + "..."
            hrows.append([meta["name"][:40], status, str(ev.get("score", 0)), str(notes)])
        ht = _table(hrows, [42*mm, 18*mm, 14*mm, 70*mm], header_bg="#37474F")
        for i, row in enumerate(hrows[1:], start=1):
            if row[1] == "Present":
                ht.setStyle(TableStyle([("BACKGROUND", (1, i), (1, i), colors.HexColor("#C8E6C9"))]))
            elif row[1] == "Weak":
                ht.setStyle(TableStyle([("BACKGROUND", (1, i), (1, i), colors.HexColor("#FFF9C4"))]))
            else:
                ht.setStyle(TableStyle([("BACKGROUND", (1, i), (1, i), colors.HexColor("#FFCDD2"))]))
        story.append(ht)

        # --- Technology table ---
        techs = ((r.get("tech") or {}).get("technologies")) or []
        story.append(Paragraph("Technology Stack", styles["SubHead"]))
        if techs:
            trows = [["Technology", "Version", "Category", "Evidence"]]
            for item in techs:
                trows.append([
                    str(item.get("name", ""))[:28],
                    str(item.get("version") or "–")[:16],
                    str(item.get("category", ""))[:22],
                    str(item.get("evidence") or "")[:50],
                ])
            story.append(_table(trows, [35*mm, 22*mm, 28*mm, 59*mm], header_bg="#00695C"))
        else:
            story.append(Paragraph("No technologies detected.", styles["Muted"]))

        # --- Vulnerability tables ---
        vuln = r.get("vuln") or {}
        vs = vuln.get("summary") or {}
        story.append(Paragraph(
            f"Vulnerability Findings  (critical={vs.get('critical',0)} high={vs.get('high',0)} "
            f"medium={vs.get('medium',0)} low={vs.get('low',0)} info={vs.get('info',0)})",
            styles["SubHead"],
        ))

        # Paths
        paths = vuln.get("path_findings") or []
        if paths:
            story.append(Paragraph("Sensitive paths", styles["Muted"]))
            prows = [["Severity", "Path", "HTTP", "Description"]]
            for pitem in paths:
                prows.append([
                    str(pitem.get("severity", "")).upper(),
                    str(pitem.get("path", ""))[:36],
                    str(pitem.get("status", "")),
                    str(pitem.get("description", ""))[:55],
                ])
            story.append(_table(prows, [18*mm, 38*mm, 14*mm, 74*mm], header_bg="#C62828"))

        # Cookies / CORS / Methods / TLS combined
        misc_rows = [["Type", "Severity", "Item", "Description"]]
        for typ, key, ikey in (
            ("Cookie", "cookie_issues", "cookie"),
            ("CORS", "cors_issues", "check"),
            ("Method", "method_issues", "check"),
            ("TLS", "tls_issues", "check"),
        ):
            for it in vuln.get(key) or []:
                misc_rows.append([
                    typ,
                    str(it.get("severity", "")).upper(),
                    str(it.get(ikey) or it.get("check") or "")[:30],
                    str(it.get("description", ""))[:60],
                ])
        if len(misc_rows) > 1:
            story.append(Paragraph("Cookies / CORS / Methods / TLS", styles["Muted"]))
            story.append(_table(misc_rows, [18*mm, 18*mm, 32*mm, 76*mm], header_bg="#E65100"))

        # CVEs
        cves = vuln.get("cves") or []
        if cves:
            story.append(Paragraph("Related CVEs (NVD)", styles["Muted"]))
            crows = [["CVE", "Severity", "Score", "Product", "Description"]]
            for c in cves:
                if c.get("cve_id") in (None, "", "N/A") and "rate" in str(c.get("description", "")).lower():
                    crows.append(["N/A", "INFO", "–", "–", str(c.get("description", ""))[:55]])
                    continue
                crows.append([
                    str(c.get("cve_id", ""))[:16],
                    str(c.get("severity", "")).upper()[:10],
                    str(c.get("score") if c.get("score") is not None else "–"),
                    f"{c.get('product','')} {c.get('version','')}".strip()[:20],
                    str(c.get("description") or "")[:45],
                ])
            if len(crows) > 1:
                story.append(_table(crows, [28*mm, 18*mm, 14*mm, 28*mm, 56*mm], header_bg="#6A1B9A"))

        if not paths and len(misc_rows) == 1 and not cves:
            story.append(Paragraph("No vulnerability findings recorded for this domain.", styles["Muted"]))

        # --- OWASP table ---
        owasp = r.get("owasp") or {}
        story.append(Paragraph(
            f"OWASP Top 10  —  Risk: {owasp.get('risk_label', '–')} ({owasp.get('risk_score', '–')}/100)",
            styles["SubHead"],
        ))
        findings = owasp.get("findings") or []
        if findings:
            orows = [["ID", "Severity", "Finding", "Detail"]]
            # issues first
            ordered = sorted(findings, key=lambda f: 0 if f.get("severity") != "pass" else 1)
            for f in ordered:
                orows.append([
                    str(f.get("category", "")),
                    str(f.get("severity", "")).upper(),
                    str(f.get("title", ""))[:40],
                    str(f.get("detail", ""))[:55],
                ])
            ot = _table(orows, [12*mm, 18*mm, 48*mm, 66*mm], header_bg="#283593")
            for i, row in enumerate(orows[1:], start=1):
                sev = row[1]
                if sev in ("CRITICAL", "HIGH"):
                    ot.setStyle(TableStyle([("BACKGROUND", (1, i), (1, i), colors.HexColor("#FFCDD2"))]))
                elif sev == "MEDIUM":
                    ot.setStyle(TableStyle([("BACKGROUND", (1, i), (1, i), colors.HexColor("#FFE0B2"))]))
                elif sev == "PASS":
                    ot.setStyle(TableStyle([("BACKGROUND", (1, i), (1, i), colors.HexColor("#C8E6C9"))]))
            story.append(ot)
        else:
            story.append(Paragraph("No OWASP assessment data for this domain.", styles["Muted"]))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC"), spaceBefore=6, spaceAfter=4))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Report includes security headers, technology fingerprinting, vulnerability checks, and OWASP Top 10:2021-oriented signals. "
        "Not a substitute for a full penetration test.",
        styles["Footer"],
    ))
    doc.build(story)
    return output_path



def load_domains(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        print(f"[!] Domains file not found: {path}")
        print("    Create a domains.txt with one domain per line (e.g. example.com)")
        return []
    domains = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    return domains


def main():
    parser = argparse.ArgumentParser(
        description="Security Header Vulnerability Scanner – checks CSP, HSTS and other headers"
    )
    parser.add_argument(
        "-d", "--domains",
        default=DEFAULT_DOMAINS_FILE,
        help=f"File containing domains (one per line). Default: {DEFAULT_DOMAINS_FILE}",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to write reports. Default: {DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write a JSON report alongside the PDF",
    )
    parser.add_argument(
        "--single",
        metavar="DOMAIN",
        help="Scan a single domain instead of reading from file",
    )
    args = parser.parse_args()

    # Prepare output dir
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.single:
        domains = [args.single]
    else:
        domains = load_domains(args.domains)

    if not domains:
        print("No domains to scan. Exiting.")
        sys.exit(1)

    print(f"[*] Starting scan of {len(domains)} domain(s) at {now_pkt().strftime('%Y-%m-%d %H:%M:%S')} PKT")
    print("-" * 60)

    results = []
    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] Scanning {domain} ...", end=" ", flush=True)
        res = scan_domain(domain)
        results.append(res)
        if res.get("error"):
            print(f"ERROR: {res['error']}")
        else:
            print(f"Grade {res['grade']} ({res['overall_score']}/100)")

    scan_time = now_pkt()
    timestamp = scan_time.strftime("%Y%m%d_%H%M%S")  # PKT
    pdf_path = out_dir / f"security_headers_report_{timestamp}.pdf"
    json_path = out_dir / f"security_headers_report_{timestamp}.json"

    print("-" * 60)
    print(f"[*] Generating PDF report: {pdf_path}")
    generate_pdf(results, str(pdf_path), scan_time)

    if args.json:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[*] JSON report written: {json_path}")

    print(f"[+] Done. Report saved to: {pdf_path}")
    # Also keep a "latest" copy for easy access
    latest = out_dir / "latest_report.pdf"
    try:
        import shutil
        shutil.copy2(pdf_path, latest)
        print(f"[+] Also saved as: {latest}")
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
