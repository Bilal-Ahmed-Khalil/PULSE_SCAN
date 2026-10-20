#!/usr/bin/env python3
"""
Technology stack detection + vulnerability checks (free resources).
Separate APIs: run_tech_scan / run_vulnerability_scan / run_full_recon
"""
from __future__ import annotations
import re, ssl, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT = 12

FINGERPRINTS = [
    {"name": "Nginx", "category": "Web Server", "header": [r"nginx/?([\d.]+)?"]},
    {"name": "Apache", "category": "Web Server", "header": [r"Apache/?([\d.]+)?"]},
    {"name": "Microsoft-IIS", "category": "Web Server", "header": [r"Microsoft-IIS/?([\d.]+)?"]},
    {"name": "Cloudflare", "category": "CDN / Security", "header": [r"cloudflare"], "html": [r"challenges\.cloudflare\.com"]},
    {"name": "Amazon CloudFront", "category": "CDN", "header": [r"cloudfront", r"x-amz-cf-"]},
    {"name": "Varnish", "category": "Cache", "header": [r"varnish", r"x-varnish"]},
    {"name": "PHP", "category": "Language", "header": [r"PHP/?([\d.]+)?", r"x-powered-by:\s*PHP/?([\d.]+)?"], "cookie": [r"PHPSESSID"]},
    {"name": "ASP.NET", "category": "Framework", "header": [r"ASP\.NET", r"x-aspnet-version:\s*([\d.]+)"], "cookie": [r"ASP\.NET_SessionId"]},
    {"name": "Express", "category": "Framework", "header": [r"x-powered-by:\s*Express"]},
    {"name": "Django", "category": "Framework", "cookie": [r"csrftoken"], "html": [r"csrfmiddlewaretoken"]},
    {"name": "Laravel", "category": "Framework", "cookie": [r"laravel_session", r"XSRF-TOKEN"]},
    {"name": "Next.js", "category": "JS Framework", "header": [r"x-powered-by:\s*Next\.js/?([\d.]+)?"], "html": [r"_next/static", r"__NEXT_DATA__"]},
    {"name": "React", "category": "JS Library", "html": [r"react(?:\.production|\.development)?(?:\.min)?\.js", r"data-reactroot"]},
    {"name": "Vue.js", "category": "JS Framework", "html": [r"vue(?:\.runtime)?(?:\.min)?\.js"]},
    {"name": "Angular", "category": "JS Framework", "html": [r"ng-version=[\"']([\d.]+)"]},
    {"name": "jQuery", "category": "JS Library", "html": [r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"]},
    {"name": "Bootstrap", "category": "CSS Framework", "html": [r"bootstrap(?:\.min)?\.(?:css|js)"]},
    {"name": "WordPress", "category": "CMS", "html": [r"wp-content", r"wp-includes", r"WordPress\s*([\d.]+)?"]},
    {"name": "Drupal", "category": "CMS", "html": [r"Drupal", r"sites/default/files"], "header": [r"x-drupal"]},
    {"name": "Joomla", "category": "CMS", "html": [r"Joomla", r"/media/jui/"]},
    {"name": "Shopify", "category": "Ecommerce", "html": [r"cdn\.shopify\.com"], "header": [r"x-shopify"]},
    {"name": "WooCommerce", "category": "Ecommerce", "html": [r"woocommerce"]},
    {"name": "Google Analytics", "category": "Analytics", "html": [r"google-analytics\.com|gtag/js\?id="]},
    {"name": "Google Tag Manager", "category": "Tag Manager", "html": [r"googletagmanager\.com/gtm\.js"]},
    {"name": "OpenSSL", "category": "Library", "header": [r"OpenSSL/?([\d.a-z]+)?"]},
]

SENSITIVE_PATHS = [
    ("/.git/HEAD", "critical", "Git repository exposed"),
    ("/.git/config", "critical", "Git config exposed"),
    ("/.env", "critical", "Environment file may expose secrets"),
    ("/.env.backup", "critical", "Backup env file"),
    ("/wp-config.php.bak", "critical", "WordPress config backup"),
    ("/backup.sql", "critical", "Database dump"),
    ("/dump.sql", "critical", "Database dump"),
    ("/actuator/env", "critical", "Spring Actuator env"),
    ("/phpinfo.php", "high", "phpinfo disclosure"),
    ("/info.php", "high", "Possible phpinfo"),
    ("/web.config", "high", "IIS web.config"),
    ("/actuator", "high", "Spring Actuator"),
    ("/debug", "high", "Debug endpoint"),
    ("/elmah.axd", "high", "ELMAH error log"),
    ("/package.json", "medium", "Node package.json"),
    ("/composer.json", "medium", "Composer manifest"),
    ("/server-status", "medium", "Apache server-status"),
    ("/swagger-ui.html", "medium", "Swagger UI"),
    ("/swagger-ui/", "medium", "Swagger UI"),
    ("/api-docs", "medium", "API docs"),
    ("/v2/api-docs", "medium", "Swagger API docs"),
    ("/graphql", "medium", "GraphQL endpoint"),
    ("/graphiql", "medium", "GraphiQL"),
    ("/xmlrpc.php", "medium", "WordPress XML-RPC"),
    ("/actuator/health", "medium", "Spring health"),
    ("/wp-login.php", "info", "WordPress login"),
    ("/wp-json/", "info", "WordPress REST API"),
    ("/admin", "info", "Admin path"),
    ("/admin/", "info", "Admin path"),
    ("/login", "info", "Login path"),
    ("/robots.txt", "info", "robots.txt"),
    ("/sitemap.xml", "info", "sitemap.xml"),
    ("/.well-known/security.txt", "info", "security.txt"),
]

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url: return ""
    if not url.startswith(("http://", "https://")): url = "https://" + url
    return url.rstrip("/")

def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s

def _fetch(url: str):
    try:
        return _session().get(url, timeout=TIMEOUT, allow_redirects=True, verify=True), None
    except requests.exceptions.SSLError:
        try:
            return _session().get(url, timeout=TIMEOUT, allow_redirects=True, verify=False), "SSL verify failed"
        except Exception as e:
            return None, str(e)
    except Exception as e:
        return None, str(e)


def detect_technologies(url: str) -> Dict[str, Any]:
    url = _normalize_url(url)
    result = {"url": url, "final_url": None, "status_code": None, "technologies": [], "headers_sample": {}, "error": None}
    if not url:
        result["error"] = "Empty URL"
        return result
    resp, err = _fetch(url)
    if resp is None:
        result["error"] = err or "Request failed"
        return result
    result["final_url"], result["status_code"] = resp.url, resp.status_code
    headers_l = {k.lower(): v for k, v in resp.headers.items()}
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via", "cf-ray", "x-drupal-cache", "x-shopify-stage"):
        if h in headers_l:
            result["headers_sample"][h] = headers_l[h]
    try:
        html = resp.text[:800000]
    except Exception:
        html = ""
    cookies = "; ".join(f"{c.name}={c.value}" for c in resp.cookies) if resp.cookies else ""

    found = {}

    def add(name, category, version=None, evidence=""):
        key = name.lower()
        ver = (version or "").strip()
        if ver in (".", "..", "-"):
            ver = ""
        if not re.match(r"^[\d]", ver or "x") and ver:
            # keep non-numeric only if looks like build tag e.g. 4.0.30319 already ok
            if not re.search(r"\d", ver):
                ver = ""
        if key not in found:
            found[key] = {"name": name, "category": category, "version": ver, "evidence": (evidence or "")[:160]}
        else:
            if ver and not found[key].get("version"):
                found[key]["version"] = ver
            if evidence and len(evidence) > len(found[key].get("evidence") or ""):
                found[key]["evidence"] = evidence[:160]

    # --- Explicit versioned headers (most reliable) ---
    explicit = [
        ("x-aspnet-version", "ASP.NET", "Framework"),
        ("x-aspnetmvc-version", "ASP.NET MVC", "Framework"),
        ("x-powered-by", None, None),  # special parse below
        ("server", None, None),
        ("x-generator", None, None),
    ]
    for hk, fixed_name, fixed_cat in explicit:
        val = headers_l.get(hk, "")
        if not val:
            continue
        if fixed_name:
            # pull version digits from value
            vm = re.search(r"([\d]+(?:\.[\d]+)+)", val)
            add(fixed_name, fixed_cat, vm.group(1) if vm else val.strip(), f"header {hk}: {val}")
        elif hk == "x-powered-by":
            # e.g. PHP/8.2.12, ASP.NET, Next.js 14.1, Express
            for name, cat, pat in (
                ("PHP", "Language", r"PHP/?([\d.]+)?"),
                ("ASP.NET", "Framework", r"ASP\.NET"),
                ("Next.js", "JS Framework", r"Next\.js/?([\d.]+)?"),
                ("Express", "Framework", r"Express"),
                ("Servlet", "Framework", r"Servlet/?([\d.]+)?"),
            ):
                m = re.search(pat, val, re.I)
                if m:
                    ver = next((g for g in m.groups() if g), None)
                    add(name, cat, ver, f"X-Powered-By: {val}")
        elif hk == "server":
            for name, cat, pat in (
                ("Nginx", "Web Server", r"nginx/?([\d.]+)?"),
                ("Apache", "Web Server", r"Apache/?([\d.]+)?"),
                ("Microsoft-IIS", "Web Server", r"(?:Microsoft-)?IIS/?([\d.]+)?"),
                ("LiteSpeed", "Web Server", r"LiteSpeed(?:/([\d.]+))?"),
                ("OpenResty", "Web Server", r"openresty/?([\d.]+)?"),
                ("Caddy", "Web Server", r"Caddy/?([\d.]+)?"),
                ("Cloudflare", "CDN / Security", r"cloudflare"),
            ):
                m = re.search(pat, val, re.I)
                if m:
                    ver = next((g for g in (m.groups() if m.groups() else []) if g), None)
                    add(name, cat, ver, f"Server: {val}")
        elif hk == "x-generator":
            parts = val.strip().split()
            if parts:
                ver = " ".join(parts[1:]) if len(parts) > 1 else ""
                vm = re.search(r"([\d]+(?:\.[\d]+)+)", val)
                add(parts[0], "CMS / Generator", vm.group(1) if vm else ver, f"X-Generator: {val}")

    # Cloudflare / CloudFront markers (often no public version)
    if any(k.startswith("cf-") for k in headers_l) or "cloudflare" in headers_l.get("server", "").lower():
        add("Cloudflare", "CDN / Security", "", "CF headers present")
    if any(k.startswith("x-amz-cf") or k == "x-amz-cf-id" for k in headers_l) or "cloudfront" in headers_l.get("via", "").lower() + headers_l.get("server", "").lower():
        add("Amazon CloudFront", "CDN", "", "CloudFront headers present")

    # Fingerprint patterns
    for fp in FINGERPRINTS:
        name, cat = fp["name"], fp["category"]
        for pat in fp.get("header", []):
            for k, v in headers_l.items():
                blob = f"{k}: {v}"
                m = re.search(pat, blob, re.I) or re.search(pat, v, re.I)
                if m:
                    ver = next((g for g in m.groups() if g), None)
                    add(name, cat, ver, f"header: {blob[:90]}")
        for pat in fp.get("html", []):
            m = re.search(pat, html, re.I)
            if m:
                ver = next((g for g in m.groups() if g), None)
                add(name, cat, ver, f"html: {m.group(0)[:80]}")
        for pat in fp.get("cookie", []):
            m = re.search(pat, cookies, re.I)
            if m:
                add(name, cat, None, f"cookie: {m.group(0)}")

    # Meta generator
    for m in re.finditer(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I):
        gen = m.group(1).strip()
        parts = gen.split()
        vm = re.search(r"([\d]+(?:\.[\d]+)+)", gen)
        add(parts[0] if parts else "Generator", "CMS / Generator",
            vm.group(1) if vm else (" ".join(parts[1:]) if len(parts) > 1 else ""),
            f"meta generator: {gen}")

    # WordPress version from generator or emoji styles or links
    m = re.search(r'content=["\']WordPress\s+([\d.]+)', html, re.I)
    if m:
        add("WordPress", "CMS", m.group(1), f"meta: WordPress {m.group(1)}")
    m = re.search(r'/wp-(?:includes|content)/[^"\']*\?ver=([\d.]+)', html, re.I)
    if m:
        add("WordPress", "CMS", m.group(1), f"asset ver={m.group(1)}")
    m = re.search(r'<link[^>]+href=["\'][^"\']*style\.min\.css\?ver=([\d.]+)', html, re.I)
    if m:
        add("WordPress", "CMS", m.group(1), f"style ver={m.group(1)}")

    # Aggressive asset version mining
    asset_pats = [
        (r"jquery[.-/]v?([\d]+\.[\d.]+)", "jQuery", "JS Library"),
        (r"jquery-migrate[.-/]v?([\d]+\.[\d.]+)", "jQuery Migrate", "JS Library"),
        (r"jquery[.-]ui[.-/]v?([\d]+\.[\d.]+)", "jQuery UI", "JS Library"),
        (r"bootstrap(?:\.bundle)?(?:\.min)?[.-/]?v?([\d]+\.[\d.]+)?", "Bootstrap", "CSS Framework"),
        (r"bootstrap/([\d]+\.[\d.]+)/", "Bootstrap", "CSS Framework"),
        (r"react(?:@|[-/.])([\d]+\.[\d.]+)", "React", "JS Library"),
        (r"vue(?:@|[-/.])(?:runtime\.)?(?:global\.)?(?:prod\.)?([\d]+\.[\d.]+)", "Vue.js", "JS Framework"),
        (r"angular(?:@|[-/.])([\d]+\.[\d.]+)", "Angular", "JS Framework"),
        (r"lodash(?:@|[-/.])([\d]+\.[\d.]+)", "Lodash", "JS Library"),
        (r"moment(?:@|[-/.])([\d]+\.[\d.]+)", "Moment.js", "JS Library"),
        (r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([\d.]+)/", None, None),
        (r"unpkg\.com/([^@/\"]+)@([\d.]+)", None, None),
        (r"jsdelivr\.net/npm/([^@/\"]+)@([\d.]+)", None, None),
        (r"/wp-content/plugins/([^/]+)/", "WP Plugin", "CMS Plugin"),
        (r"woocommerce.*?ver=([\d.]+)", "WooCommerce", "Ecommerce"),
        (r"shopify.*?([\d]+\.[\d.]+)", "Shopify", "Ecommerce"),
    ]
    for m in re.finditer(r'(?:src|href)=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1)
        for pat, name, cat in asset_pats:
            mm = re.search(pat, src, re.I)
            if not mm:
                continue
            if name is None:
                # CDN lib@version
                add(mm.group(1), "JS Library", mm.group(2), f"CDN: {src[:100]}")
            elif name == "WP Plugin":
                add(f"Plugin: {mm.group(1)}", "CMS Plugin", "", f"path: {src[:80]}")
            else:
                ver = next((g for g in mm.groups() if g and re.match(r"[\d.]+$", g)), None)
                add(name, cat, ver, f"asset: {src[:100]}")

    # __NEXT_DATA__ build id is not version but next header often is
    if "__NEXT_DATA__" in html or "/_next/static/" in html:
        add("Next.js", "JS Framework", headers_l.get("x-powered-by", "").replace("Next.js", "").strip(" /"), "Next.js markers in HTML")

    # Angular version attribute
    m = re.search(r'ng-version=["\']([\d.]+)', html, re.I)
    if m:
        add("Angular", "JS Framework", m.group(1), f"ng-version={m.group(1)}")

    result["technologies"] = sorted(found.values(), key=lambda x: (x["category"], x["name"]))
    return result



def _check_one_path(base, path, severity, description):
    try:
        r = _session().get(urljoin(base + "/", path.lstrip("/")), timeout=8, allow_redirects=False, verify=True)
        if r.status_code == 200 and len(r.content) > 0:
            if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt") or len(r.content) < 80000:
                body = (r.text or "")[:1500].lower()
                if "not found" in body and "404" in body and len(r.content) > 5000:
                    return None
                return {"path": path, "status": r.status_code, "severity": severity, "description": description}
        elif r.status_code in (401, 403) and severity in ("critical", "high"):
            return {"path": path, "status": r.status_code, "severity": "low", "description": f"{description} (forbidden)"}
    except Exception:
        pass
    return None

def check_sensitive_paths(url: str) -> List[Dict[str, Any]]:
    url = _normalize_url(url)
    findings = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_check_one_path, url, p, s, d) for p, s, d in SENSITIVE_PATHS]
        for fut in as_completed(futs):
            item = fut.result()
            if item: findings.append(item)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x.get("severity", "info"), 9))
    return findings

def check_cookie_flags(url: str) -> List[Dict[str, Any]]:
    url = _normalize_url(url); issues = []
    resp, _ = _fetch(url)
    if resp is None: return issues
    try: cookie_headers = resp.headers.get_list("Set-Cookie")
    except Exception:
        sc = resp.headers.get("Set-Cookie"); cookie_headers = [sc] if sc else []
    for ch in cookie_headers:
        if not ch: continue
        name = ch.split("=")[0].strip(); lower = ch.lower(); missing = []
        if "secure" not in lower and url.startswith("https"): missing.append("Secure")
        if "httponly" not in lower: missing.append("HttpOnly")
        if "samesite" not in lower: missing.append("SameSite")
        if missing:
            sev = "medium" if ("Secure" in missing or "HttpOnly" in missing) else "low"
            issues.append({"cookie": name, "severity": sev, "description": f"Missing flags: {', '.join(missing)}"})
    return issues

def check_cors(url: str) -> List[Dict[str, Any]]:
    url = _normalize_url(url); issues = []
    try:
        r = _session().get(url, timeout=TIMEOUT, headers={"Origin": "https://evil-attacker.example"}, allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            issues.append({"check": "CORS", "severity": "medium", "description": "Access-Control-Allow-Origin: *"})
        elif acao and "evil-attacker" in acao:
            sev = "high" if acac.lower() == "true" else "medium"
            issues.append({"check": "CORS", "severity": sev, "description": f"Reflects Origin ({acao})" + (" + credentials" if acac.lower() == "true" else "")})
    except Exception:
        pass
    return issues

def check_http_methods(url: str) -> List[Dict[str, Any]]:
    url = _normalize_url(url); issues = []
    try:
        r = _session().request("OPTIONS", url, timeout=8, allow_redirects=True)
        allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
        if allow:
            dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
            if dangerous:
                issues.append({"check": "HTTP Methods", "severity": "medium", "description": f"Dangerous methods: {', '.join(dangerous)}"})
        try:
            t = _session().request("TRACE", url, timeout=6, allow_redirects=False)
            if t.status_code == 200:
                issues.append({"check": "HTTP TRACE", "severity": "medium", "description": "TRACE method enabled"})
        except Exception:
            pass
    except Exception:
        pass
    return issues

def check_tls_basic(url: str) -> List[Dict[str, Any]]:
    url = _normalize_url(url); issues = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        issues.append({"check": "HTTPS", "severity": "high", "description": "Site not using HTTPS"}); return issues
    host, port = parsed.hostname or "", parsed.port or 443
    if not host: return issues
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert, ver = ssock.getpeercert(), ssock.version()
                if ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    issues.append({"check": "TLS Version", "severity": "high", "description": f"Weak TLS: {ver}"})
                if cert and cert.get("notAfter"):
                    issues.append({"check": "TLS Certificate", "severity": "info", "description": f"Valid until {cert.get('notAfter')} | {ver}"})
    except ssl.SSLCertVerificationError as e:
        issues.append({"check": "TLS Certificate", "severity": "high", "description": f"Cert verify failed: {e}"})
    except Exception as e:
        issues.append({"check": "TLS", "severity": "info", "description": f"TLS probe: {e}"})
    return issues

def lookup_cves_nvd(product: str, version: str = "", max_results: int = 4) -> List[Dict[str, Any]]:
    if not product or len(product) < 2: return []
    if product.lower() in ("server", "javascript", "html", "css", "http", "cdn"): return []
    keyword = f"{product} {version}".strip() if version else product
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                         params={"keywordSearch": keyword, "resultsPerPage": max_results},
                         headers={"User-Agent": USER_AGENT}, timeout=25)
        if r.status_code in (403, 429):
            return [{"cve_id": "N/A", "severity": "info", "score": None,
                     "description": "NVD rate limited – retry later", "product": product, "version": version}]
        if r.status_code != 200: return []
        data = r.json()
    except Exception as e:
        return [{"cve_id": "N/A", "severity": "info", "score": None, "description": f"NVD error: {e}", "product": product, "version": version}]
    out = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:220]
        score, severity = None, "unknown"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                score, severity = m.get("baseScore"), (m.get("baseSeverity") or severity).lower()
                break
        out.append({"cve_id": cve_id, "severity": severity, "score": score, "description": desc, "product": product, "version": version})
    return out

def run_tech_scan(url: str) -> Dict[str, Any]:
    return detect_technologies(url)

def run_vulnerability_scan(url: str, technologies=None, include_cves: bool = True) -> Dict[str, Any]:
    url = _normalize_url(url)
    report = {"url": url, "path_findings": [], "cookie_issues": [], "cors_issues": [], "method_issues": [],
              "tls_issues": [], "cves": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "error": None}
    if not url:
        report["error"] = "Empty URL"; return report
    with ThreadPoolExecutor(max_workers=5) as ex:
        fp, fc, fco, fm, ft = ex.submit(check_sensitive_paths, url), ex.submit(check_cookie_flags, url), ex.submit(check_cors, url), ex.submit(check_http_methods, url), ex.submit(check_tls_basic, url)
        report["path_findings"], report["cookie_issues"] = fp.result(), fc.result()
        report["cors_issues"], report["method_issues"], report["tls_issues"] = fco.result(), fm.result(), ft.result()
    if include_cves:
        techs = technologies
        if techs is None:
            techs = detect_technologies(url).get("technologies", [])
        seen = set()
        for t in techs or []:
            name, ver = t.get("name", ""), t.get("version", "")
            if not name or name.lower() in seen: continue
            if not ver and t.get("category") not in ("CMS", "Web Server", "Framework", "Ecommerce", "Language"): continue
            seen.add(name.lower())
            report["cves"].extend(lookup_cves_nvd(name, ver, max_results=3))
            time.sleep(6.5)
            if len(report["cves"]) >= 18: break
    def bump(sev):
        sev = (sev or "info").lower()
        if sev not in report["summary"]: sev = "info"
        report["summary"][sev] = report["summary"].get(sev, 0) + 1
    for bucket in ("path_findings", "cookie_issues", "cors_issues", "method_issues", "tls_issues"):
        for f in report[bucket]: bump(f.get("severity"))
    for f in report["cves"]:
        if f.get("cve_id") and f.get("cve_id") != "N/A": bump(f.get("severity"))
    return report

def run_full_recon(url: str, include_cves: bool = True) -> Dict[str, Any]:
    tech = detect_technologies(url)
    vuln = run_vulnerability_scan(url, technologies=tech.get("technologies"), include_cves=include_cves)
    return {"url": url, "tech": tech, "vuln": vuln, "error": tech.get("error") or vuln.get("error")}

# Back-compat
def run_tech_and_vuln_scan(url: str, include_cves: bool = True) -> Dict[str, Any]:
    full = run_full_recon(url, include_cves=include_cves)
    tech, vuln = full.get("tech") or {}, full.get("vuln") or {}
    return {
        "url": url, "technologies": tech.get("technologies", []), "status_code": tech.get("status_code"),
        "final_url": tech.get("final_url"), "headers_sample": tech.get("headers_sample", {}),
        "path_findings": vuln.get("path_findings", []), "cookie_issues": vuln.get("cookie_issues", []),
        "cors_issues": vuln.get("cors_issues", []), "method_issues": vuln.get("method_issues", []),
        "tls_issues": vuln.get("tls_issues", []), "cves": vuln.get("cves", []),
        "summary": vuln.get("summary", {}), "error": full.get("error"),
    }
