import re
import socket
import time
import logging
import threading
import requests
import validators
import certifi
from datetime import datetime
from concurrent import futures

EXPLOIT_INDEX = {}

# ─── single logger ───────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── NVD keyword aliases ───────────────────────────────────────────────────────
_KEYWORD_ALIASES = {
    'wordpress':   ['WordPress Core', 'WordPress'],
    'drupal':      ['Drupal Core', 'Drupal'],
    'joomla':      ['Joomla! Core', 'Joomla'],
    'apache':      ['Apache HTTP Server', 'Apache httpd'],
    'nginx':       ['nginx'],
    'jquery':      ['jQuery'],
    'php':         ['PHP'],
    'laravel':     ['Laravel Framework', 'Laravel'],
    'django':      ['Django'],
    'flask':       ['Flask'],
    'node.js':     ['Node.js'],
    'openssl':     ['OpenSSL'],
    'tomcat':      ['Apache Tomcat', 'Tomcat'],
    'woocommerce': ['WooCommerce'],
    'yoast seo':   ['Yoast SEO', 'wordpress-seo'],
    'nginx':       ['nginx', 'F5 nginx', 'nginx web server'],
}

# ─── global constants ────────────────────────────────────────────────────────
REQUEST_TIMEOUT   = 7     # every outbound HTTP call
NVD_MAX_WORKERS   = 4     # parallel NVD threads  (safe under public rate-limit)
SUBDOMAIN_WORKERS = 5     # parallel subdomain-source threads
DNS_WORKERS       = 10    # parallel DNS brute-force threads
CACHE_TTL         = 300   # 5 minutes
MAX_SUBDOMAINS    = 50

# ─── thread-safe in-process cache ────────────────────────────────────────────
_cache_lock = threading.Lock()
_sub_cache  = {}   # { (session_id, domain) : (ts, result) }
_nvd_cache  = {}   # { cache_key_str        : (ts, result) }


def _get_cache(store, key):
    with _cache_lock:
        entry = store.get(key)
        if entry:
            ts, data = entry
            if time.time() - ts < CACHE_TTL:
                return data
    return None


def _set_cache(store, key, data):
    with _cache_lock:
        store[key] = (time.time(), data)


# ─────────────────────────────────────────────────────────────────────────────
# STATIC CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
]

SOURCE_RANK = {
    'wappalyzer':   4,
    'cpe':          3,
    'builtwith':    2,
    'headers':      1,
    'html_meta':    1,
    'html_scripts': 0,
    'html_links':   0,
}

HIGH_PRIORITY_PREFIXES = [
    'admin', 'api', 'dev', 'staging', 'test', 'vpn', 'mail',
    'remote', 'portal', 'dashboard', 'beta', 'app', 'login',
    'secure', 'internal', 'smtp', 'ftp', 'ssh', 'git', 'ci',
    'jenkins', 'jira', 'monitor', 'status',
]

COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
    'admin', 'portal', 'api', 'dev', 'staging', 'test', 'beta',
    'app', 'login', 'secure', 'vpn', 'remote', 'dashboard',
    'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'media',
    'img', 'images', 'm', 'mobile', 'ns1', 'ns2', 'mx', 'docs',
    'help', 'support', 'status', 'monitor', 'git', 'ci', 'jenkins',
]

CPE_MAP = {
    "wordpress":          "cpe:2.3:a:wordpress:wordpress",
    "nginx":              "cpe:2.3:a:f5:nginx",
    "apache":             "cpe:2.3:a:apache:http_server",
    "apache http server": "cpe:2.3:a:apache:http_server",
    "php":                "cpe:2.3:a:php:php",
    "jquery":             "cpe:2.3:a:jquery:jquery",
    "react":              "cpe:2.3:a:facebook:react",
    "bootstrap":          "cpe:2.3:a:getbootstrap:bootstrap",
    "vue.js":             "cpe:2.3:a:vuejs:vue",
    "angular":            "cpe:2.3:a:angular:angular",
    "drupal":             "cpe:2.3:a:drupal:drupal",
    "joomla":             "cpe:2.3:a:joomla:joomla",
    "laravel":            "cpe:2.3:a:laravel:laravel",
    "django":             "cpe:2.3:a:djangoproject:django",
    "flask":              "cpe:2.3:a:palletsprojects:flask",
    "mysql":              "cpe:2.3:a:mysql:mysql",
    "postgresql":         "cpe:2.3:a:postgresql:postgresql",
    "mongodb":            "cpe:2.3:a:mongodb:mongodb",
    "redis":              "cpe:2.3:a:redis:redis",
    "elasticsearch":      "cpe:2.3:a:elastic:elasticsearch",
    "iis":                "cpe:2.3:a:microsoft:internet_information_services",
    "microsoft iis":      "cpe:2.3:a:microsoft:internet_information_services",
    "openssl":            "cpe:2.3:a:openssl:openssl",
    "woocommerce":        "cpe:2.3:a:woocommerce:woocommerce",
    "magento":            "cpe:2.3:a:magento:magento",
    "node.js":            "cpe:2.3:a:nodejs:node.js",
    "express":            "cpe:2.3:a:expressjs:express",
    "tomcat":             "cpe:2.3:a:apache:tomcat",
    "apache tomcat":      "cpe:2.3:a:apache:tomcat",
    "jenkins":            "cpe:2.3:a:jenkins:jenkins",
    "gitlab":             "cpe:2.3:a:gitlab:gitlab",
    "jquery ui":          "cpe:2.3:a:jquery:jquery_ui",
    "lodash":             "cpe:2.3:a:lodash:lodash",
    "moment.js":          "cpe:2.3:a:momentjs:moment",
}


# ─────────────────────────────────────────────────────────────────────────────
# SHARED HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def normalize_domain(domain):
    domain = domain.strip().lower()
    domain = domain.replace('https://', '').replace('http://', '')
    return domain.split('/')[0]


def validate_domain(domain):
    if not validators.domain(domain):
        return False, "Invalid domain name"
    return True, None


def get_header_grade(score):
    if score >= 90: return 'A'
    if score >= 70: return 'B'
    if score >= 50: return 'C'
    if score >= 30: return 'D'
    return 'F'


def extract_name_version(text):
    m = re.match(r'^([a-zA-Z\s\-\.]+)[/]([\d][\d\.]+)', text.strip())
    if m:
        version = m.group(2).strip()
        if version.count('.') < 2:
            version = None
        return m.group(1).strip(), version

    m = re.match(r'^([a-zA-Z\s\-]+)\s([\d][\d\.]+)', text.strip())
    if m:
        version = m.group(2).strip()
        if version.count('.') < 2:
            version = None
        return m.group(1).strip(), version

    return text.strip(), None


def extract_version_from_url(url):
    m = re.search(r'[\-/]([\d]+\.[\d]+[\.\d]*)', url)
    return m.group(1) if m else None


def _merge_tech(existing, new):
    """
    Order-independent merge — always keeps the most informative tech entry.
    Prefers: version present > higher SOURCE_RANK.
    """
    has_ver_new = bool(new.get('version'))
    has_ver_old = bool(existing.get('version'))
    if has_ver_new and not has_ver_old:
        return new
    if has_ver_old and not has_ver_new:
        return existing
    return new if SOURCE_RANK.get(new.get('source', ''), 0) > SOURCE_RANK.get(existing.get('source', ''), 0) else existing


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(headers_result, cves_result=None, tech_stack=None, subdomains_result=None):
    score = 0.0
 
    # 1. Header score (max 25 pts)
    score += round((headers_result.get('header_score', 0) / 100) * 25, 1)
 
    # 2. CVE score (max 40 pts)
    if cves_result:
        ded  = min(cves_result.get('critical', 0) * 8, 24)
        ded += min(cves_result.get('high',     0) * 4, 12)
        ded += min(cves_result.get('medium',   0) * 1,  4)
        if cves_result.get('high_confidence', 0) > 0:
            ded += min(cves_result['high_confidence'] * 3, 10)
 
       
        exploitable = sum(
            1 for c in (cves_result.get('cves') or [])
            if c.get('exploit_available')
        )
        ded += min(exploitable * 2, 6)
        # ─────────────────────────────────────────────────────────────────
 
        score += round(max(0, 40 - ded), 1)
    else:
        score += 40
 
    # 3. SSL (5 pts)
    if not headers_result.get('ssl_issue', False):
        score += 5
 
    # 4. HTTPS + redirect (5 + 5 pts)
    if headers_result.get('https', False):
        score += 5
    if headers_result.get('https_redirect', False):
        score += 5
 
    # 5. Tech exposure (max 10 pts)
    if tech_stack:
        versioned = [t for t in tech_stack.get('technologies', []) if t.get('version')]
        if   len(versioned) == 0: score += 10
        elif len(versioned) <= 2: score += 7
        elif len(versioned) <= 5: score += 4
 
    # 6. Subdomain exposure (max 10 pts)
    if subdomains_result and not subdomains_result.get('scan_failed', False):
        count = subdomains_result.get('total_found', 0)
        if   count < 15:  score += 10
        elif count < 50:  score += 6
        elif count < 100: score += 3
 
    score = int(round(max(0, min(100, score))))
 
    if   score >= 80: label, color, icon = 'Low Risk',      '#3fb950', 'fas fa-shield-alt'
    elif score >= 50: label, color, icon = 'Medium Risk',   '#d29922', 'fas fa-exclamation-triangle'
    elif score >= 30: label, color, icon = 'High Risk',     '#f85149', 'fas fa-exclamation-circle'
    else:             label, color, icon = 'Critical Risk', '#ff4444', 'fas fa-skull-crossbones'
 
    return {'score': score, 'label': label, 'color': color, 'icon': icon}


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — HEADERS
# ─────────────────────────────────────────────────────────────────────────────

def scan_headers(domain, mode='full'):
    timeout        = 4 if mode == 'quick' else REQUEST_TIMEOUT
    https_url      = 'https://' + domain
    http_url       = 'http://'  + domain
    ua             = {'User-Agent': 'Mozilla/5.0 (VulnWatch Security Scanner)'}

    result = {
        'final_url': None, 'https': False, 'https_redirect': False,
        'server': None, 'powered_by': None, 'security_headers': {},
        'missing_headers': [], 'status_code': None,
        'header_score': 0, 'header_grade': 'F',
        'error': None, 'ssl_issue': False,
    }

    try:
        response = requests.get(https_url, timeout=timeout,
                                allow_redirects=True, headers=ua,
                                verify=certifi.where())
    except requests.exceptions.SSLError:
        logger.warning(f"SSL failed, retrying HTTP for {domain}")
        result['ssl_issue'] = True
        try:
            response = requests.get(http_url, timeout=timeout,
                                    allow_redirects=True, headers=ua)
        except Exception:
            result['error'] = 'SSL error and HTTP fallback failed'
            return result
    except requests.exceptions.ConnectionError:
        result['error'] = 'Could not connect to domain'
        return result
    except requests.exceptions.Timeout:
        result['error'] = 'Request timed out'
        return result
    except Exception:
        result['error'] = 'Unexpected error during scan'
        logger.error(f"Unexpected error scanning {https_url}", exc_info=True)
        return result

    result['status_code'] = response.status_code
    result['final_url']   = response.url
    result['https']       = response.url.startswith('https://')
    hdrs                  = response.headers
    result['server']      = hdrs.get('Server',       'Hidden')
    result['powered_by']  = hdrs.get('X-Powered-By', 'Hidden')

    for h in SECURITY_HEADERS:
        v = hdrs.get(h)
        if v:
            result['security_headers'][h] = v
        else:
            result['missing_headers'].append(h)

    present                = len(result['security_headers'])
    result['header_score'] = round((present / len(SECURITY_HEADERS)) * 100)
    result['header_grade'] = get_header_grade(result['header_score'])

    # No second HTTP request needed — non-empty history + https final URL = redirect
    if result['https'] and not result['ssl_issue']:
        result['https_redirect'] = len(response.history) > 0

    return result


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — TECH STACK
# ─────────────────────────────────────────────────────────────────────────────

def scan_tech_stack(domain, html_content=None, headers=None):
    result = {'technologies': [], 'error': None}
    try:
        # Wappalyzer — uses passed-in html + headers, no extra request
        try:
            from app.scanner.wappalyzer_engine import wappalyzer_scan
            for tname, tdata in wappalyzer_scan(
                headers=headers, html=html_content, url='https://' + domain
            ).items():
                result['technologies'].append({
                    'name': tdata['name'], 'category': 'unknown',
                    'source': 'wappalyzer', 'version': tdata['version'],
                })
        except Exception:
            logger.warning("Wappalyzer failed", exc_info=True)

        
        try:
            import builtwith
            for category, techs in builtwith.parse('https://' + domain).items():
                for tech in techs:
                    result['technologies'].append({
                        'name': tech, 'category': category,
                        'source': 'builtwith', 'version': None,
                    })
        except Exception:
            logger.warning(f"builtwith failed for {domain}", exc_info=True)

        # Header fingerprinting
        if headers:
            for value, category in [
                (headers.get('Server',       ''), 'Web Server'),
                (headers.get('X-Powered-By', ''), 'Programming Language'),
                (headers.get('X-Generator',  ''), 'CMS'),
            ]:
                if value and value != 'Hidden':
                    name, version = extract_name_version(value)
                    result['technologies'].append({
                        'name': name, 'category': category,
                        'source': 'headers', 'version': version,
                    })

        # HTML fingerprinting
        if html_content:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')

            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen:
                name, version = extract_name_version(gen.get('content', ''))
                result['technologies'].append({
                    'name': name, 'category': 'CMS',
                    'source': 'html_meta', 'version': version,
                })

            sig = {
                'jquery':    ('jQuery',    'JavaScript Library',   True),
                'react':     ('React',     'JavaScript Framework', False),
                'vue':       ('Vue.js',    'JavaScript Framework', False),
                'angular':   ('Angular',   'JavaScript Framework', False),
                'bootstrap': ('Bootstrap', 'CSS Framework',        True),
            }
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                if 'wordpress' in src or 'wp-content' in src:
                    result['technologies'].append({
                        'name': 'WordPress', 'category': 'CMS',
                        'source': 'html_scripts', 'version': None,
                    })
                for kw, (name, cat, versioned) in sig.items():
                    if kw in src:
                        result['technologies'].append({
                            'name': name, 'category': cat,
                            'source': 'html_scripts',
                            'version': extract_version_from_url(src) if versioned else None,
                        })

            for link in soup.find_all('link', href=True):
                href = link['href'].lower()
                if 'wp-content' in href or 'wordpress' in href:
                    result['technologies'].append({
                        'name': 'WordPress', 'category': 'CMS',
                        'source': 'html_links', 'version': None,
                    })
                if 'bootstrap' in href:
                    result['technologies'].append({
                        'name': 'Bootstrap', 'category': 'CSS Framework',
                        'source': 'html_links',
                        'version': extract_version_from_url(href),
                    })

        # Deterministic dedup
        seen = {}
        for tech in result['technologies']:
            key = tech['name'].lower()
            seen[key] = _merge_tech(seen[key], tech) if key in seen else tech
        result['technologies'] = list(seen.values())

    except Exception:
        logger.error(f"Tech stack scan failed for {domain}", exc_info=True)
        result['error'] = 'Tech stack detection failed'

    return result


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — SUBDOMAIN DISCOVERY  (5 parallel sources)
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_crtsh(domain):
    found = set()
    url   = f"https://crt.sh/?q=%.{domain}&output=json"
    for wait in [0, 2, 5]:
        time.sleep(wait)
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT,
                             headers={'User-Agent': 'Mozilla/5.0 (VulnWatch Security Scanner)'})
            if r.status_code in [429, 403, 503]:
                continue
            r.raise_for_status()
            for entry in r.json():
                for sub in entry.get('name_value', '').split('\n'):
                    sub = sub.strip().lower()
                    if sub and not sub.startswith('*') and sub != domain and sub.endswith('.' + domain):
                        found.add(sub)
            return found
        except Exception:
            continue
    return found


def _fetch_hackertarget(domain):
    found = set()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=REQUEST_TIMEOUT,
            headers={'User-Agent': 'Mozilla/5.0 (VulnWatch Security Scanner)'}
        )
        r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.strip().split(',')
            if parts:
                sub = parts[0].strip().lower()
                if sub.endswith('.' + domain) and sub != domain:
                    found.add(sub)
    except Exception:
        pass
    return found


def _fetch_alienvault(domain):
    found = set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=REQUEST_TIMEOUT,
            headers={'User-Agent': 'Mozilla/5.0 (VulnWatch Security Scanner)'}
        )
        r.raise_for_status()
        for entry in r.json().get('passive_dns', []):
            host = entry.get('hostname', '').strip().lower()
            if host.endswith('.' + domain) and host != domain:
                found.add(host)
    except Exception:
        pass
    return found


def _fetch_bufferover(domain):
    found = set()
    try:
        r = requests.get(
            f"https://tls.bufferover.run/dns?q=.{domain}",
            timeout=REQUEST_TIMEOUT,
            headers={'User-Agent': 'Mozilla/5.0 (VulnWatch Security Scanner)'}
        )
        r.raise_for_status()
        for entry in r.json().get('FDNS_A', []) or []:
            parts = entry.split(',')
            if len(parts) >= 2:
                sub = parts[1].strip().lower()
                if sub.endswith('.' + domain) and sub != domain:
                    found.add(sub)
    except Exception:
        pass
    return found


def _dns_probe(fqdn):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((fqdn, 80))
        sock.close()
        return fqdn
    except Exception:
        return None


def _fetch_dns_bruteforce(domain):
    """
    Direct DNS resolution of common prefixes.
    No external API — this source never returns N/A.
    """
    found = set()
    with futures.ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
        for hit in ex.map(_dns_probe, [f"{p}.{domain}" for p in COMMON_SUBDOMAINS]):
            if hit:
                found.add(hit)
    return found


def scan_subdomains(domain, session_id=None):
    cache_key = (session_id, domain)
    cached    = _get_cache(_sub_cache, cache_key)
    if cached is not None:
        logger.info(f"Subdomain cache HIT for {domain}")
        return cached

    all_found    = set()
    sources_used = []

    with futures.ThreadPoolExecutor(max_workers=SUBDOMAIN_WORKERS) as ex:
        fmap = {
            ex.submit(fn, domain): name
            for name, fn in {
                'crt.sh':         _fetch_crtsh,
                'hackertarget':   _fetch_hackertarget,
                'alienvault':     _fetch_alienvault,
                'bufferover':     _fetch_bufferover,
                'dns_bruteforce': _fetch_dns_bruteforce,
            }.items()
        }
        for future in futures.as_completed(fmap):
            name = fmap[future]
            try:
                subs = future.result()
                if subs:
                    all_found.update(subs)
                    sources_used.append(name)
            except Exception:
                logger.warning(f"Subdomain source {name} raised", exc_info=True)

    scan_failed = len(sources_used) == 0

    result = {
        'subdomains':    [],
        'total_found':   0,
        'limited':       False,
        'limit_message': None,
        'error':         'No subdomains found across all sources' if scan_failed else None,
        'confidence':    'low' if scan_failed else 'high',
        'sources_used':  sources_used,
        'scan_failed':   scan_failed,
    }

    if not scan_failed:
        result['total_found'] = len(all_found)

        if len(all_found) > MAX_SUBDOMAINS:
            result['limited']       = True
            result['limit_message'] = (
                f"Showing top {MAX_SUBDOMAINS} of {len(all_found)} subdomains found."
            )

        def _sort_key(sub):
            prefix = sub.replace('.' + domain, '')
            return (0 if prefix in HIGH_PRIORITY_PREFIXES else 1, sub)

        result['subdomains'] = sorted(all_found, key=_sort_key)[:MAX_SUBDOMAINS]

    if not result['scan_failed']:
        _set_cache(_sub_cache, cache_key, result)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — CVE MATCHING
# ─────────────────────────────────────────────────────────────────────────────

def build_cpe(tech_name, version=None):
    """Returns (cpe_base, version) tuple, or (None, None) if unknown tech."""
    base = CPE_MAP.get(tech_name.lower().strip())
    if not base:
        return None, None
    return base, version


def parse_cve_item(cve, tech_name, version=None, source='keyword', confidence='low'):
    cve_id       = cve.get('id', 'N/A')
    descriptions = cve.get('descriptions', [])
    description  = next((d['value'] for d in descriptions if d['lang'] == 'en'),
                        'No description available')
    if description.startswith('Rejected'):
        return None
 
    score, severity = None, 'UNKNOWN'
    metrics = cve.get('metrics', {})
    if metrics.get('cvssMetricV31'):
        c        = metrics['cvssMetricV31'][0]['cvssData']
        score    = c.get('baseScore')
        severity = c.get('baseSeverity', 'UNKNOWN')
    elif metrics.get('cvssMetricV30'):
        c        = metrics['cvssMetricV30'][0]['cvssData']
        score    = c.get('baseScore')
        severity = c.get('baseSeverity', 'UNKNOWN')
    elif metrics.get('cvssMetricV2'):
        c        = metrics['cvssMetricV2'][0]['cvssData']
        score    = c.get('baseScore')
        severity = 'MEDIUM'
 
    # ── Exploit-DB enrichment ─────────────────────────────────────────────────
   
    exploits          = EXPLOIT_INDEX.get(cve_id, [])
    exploit_available = len(exploits) > 0
    exploit_urls      = exploits[:3]   
    # ─────────────────────────────────────────────────────────────────────────
 
    return {
        'id':                cve_id,
        'technology':        tech_name,
        'version':           version,
        'description':       description[:200] + '...' if len(description) > 200 else description,
        'score':             score,
        'severity':          severity,
        'kev':               bool(cve.get('cisaExploitAdd')),
        'published':         cve.get('published', '')[:10],
        'source':            source,
        'confidence':        confidence,
        'url':               f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        'exploit_available': exploit_available,   # NEW
        'exploit_urls':      exploit_urls,        # NEW  list of {url, title}
    }


def _fetch_nvd(params, tech_name, version, source, confidence, min_year):
    """Raw NVD call — always hits network. Only called via cached wrappers."""
    cves = []
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 429:
            logger.warning("NVD rate limited — backing off 6s")
            time.sleep(6)
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, timeout=REQUEST_TIMEOUT
            )
        r.raise_for_status()
        for item in r.json().get('vulnerabilities', []):
            cve = item.get('cve', {})
            if cve.get('vulnStatus') in ['Rejected', 'REJECTED']:
                continue
            try:
                if int(cve.get('published', '')[:4]) < min_year:
                    continue
            except ValueError:
                continue
            parsed = parse_cve_item(cve, tech_name, version=version,
                                    source=source, confidence=confidence)
            if parsed:
                cves.append(parsed)
    except requests.exceptions.Timeout:
        logger.warning(f"NVD timeout for {tech_name}")
    except Exception:
        logger.error(f"NVD fetch failed for {tech_name}", exc_info=True)
    return cves


def _fetch_nvd_by_range(tech_name, cpe_base, version, min_year=2020):
    """
    If version is None — skip this entirely.
    A wildcard CPE query with no versionEndIncluding returns ALL CVEs
    for that product across all versions, which we cannot call 'verified'
    without knowing what version the site is actually running.
    """
    if not version:          
        return []           

    
    virtual_match = f"{cpe_base}:*:*:*:*:*:*:*:*"
 
    params = {
        'virtualMatchString':   virtual_match,
        'resultsPerPage':       50,
    }
    if version:
        params['versionEndIncluding'] = version
 
    cache_key = f"range:{tech_name}:{version}:{min_year}"
    cached    = _get_cache(_nvd_cache, cache_key)
    if cached is not None:
        return cached
 
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=REQUEST_TIMEOUT
        )
 
        if r.status_code == 429:
            logger.warning("NVD rate limited — backing off 6s")
            time.sleep(6)
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, timeout=REQUEST_TIMEOUT
            )
 
        r.raise_for_status()
 
        for item in r.json().get('vulnerabilities', []):
            cve = item.get('cve', {})
            if cve.get('vulnStatus') in ['Rejected', 'REJECTED']:
                continue
            try:
                pub_year = int(cve.get('published', '')[:4])
                if pub_year < min_year:
                    continue
            except (ValueError, TypeError):
                continue
 
            parsed = parse_cve_item(
                cve, tech_name,
                version=version,
                source='cpe',
                confidence='high'
            )
            if parsed:
                cves.append(parsed)
 
    except requests.exceptions.Timeout:
        logger.warning(f"NVD range query timeout for {tech_name}")
    except Exception:
        logger.error(f"NVD range query failed for {tech_name}", exc_info=True)
 
    _set_cache(_nvd_cache, cache_key, cves)
    return cves

def fetch_cves_by_cpe(tech_name, version, min_year=2020):
    cpe_base, ver = build_cpe(tech_name, version)
    if not cpe_base:
        return []
 
    
    range_results = _fetch_nvd_by_range(tech_name, cpe_base, ver, min_year)
 
    
    if not range_results and ver:
        exact_cpe = f"{cpe_base}:{ver}:*:*:*:*:*:*:*"
        key       = f"cpe_exact:{tech_name}:{ver}:{min_year}"
        cached    = _get_cache(_nvd_cache, key)
        if cached is not None:
            return cached
        exact = _fetch_nvd(
            {'cpeName': exact_cpe, 'resultsPerPage': 50},
            tech_name, ver, 'cpe', 'high', min_year
        )
        _set_cache(_nvd_cache, key, exact)
        return exact
 
    return range_results
 

def fetch_cves_by_keyword(tech_name, version=None, min_year=2020, confidence='low'):
    tech_lower = tech_name.lower()
    aliases    = _KEYWORD_ALIASES.get(tech_lower, [tech_name])
 
    all_cves = []
 
    for alias in aliases:
        keyword = f"{alias} {version}" if version else alias
        key     = f"kw:{keyword}:{min_year}"
        cached  = _get_cache(_nvd_cache, key)
        if cached is not None:
            all_cves.extend(cached)
            continue
 
        result = _fetch_nvd(
            {'keywordSearch': keyword, 'resultsPerPage': 50},
            tech_name, version, 'keyword', confidence, min_year
        )
        _set_cache(_nvd_cache, key, result)
        all_cves.extend(result)
 
    # Deduplicate
    seen = {}
    for cve in all_cves:
        if cve['id'] not in seen:
            seen[cve['id']] = cve
    return list(seen.values())


def _fetch_cves_for_tech(tech):
    name    = tech.get('name', '').strip()
    version = tech.get('version')
    if not name:
        return []
 
    min_year = 2020   # always 2020 — never restrict by version presence
 
    # Source 2: NVD virtualMatchString range query (high confidence)
    cpe_cves = fetch_cves_by_cpe(name.lower(), version, min_year=min_year)
 
    # Source 3: NVD keyword search (medium/low confidence, catches the rest)
    kw_conf = 'medium'
    kw_cves  = fetch_cves_by_keyword(name, version, min_year=min_year,
                                     confidence=kw_conf)
 
    # Merge — highest confidence wins per CVE ID
    confidence_rank = {'high': 3, 'medium': 2, 'low': 1}
    merged = {}
    for cve in kw_cves + cpe_cves:
        cid = cve['id']
        if cid not in merged or (
            confidence_rank.get(cve.get('confidence', 'low'), 1) >
            confidence_rank.get(merged[cid].get('confidence', 'low'), 1)
        ):
            merged[cid] = cve
 
    return list(merged.values())
 


def match_cves(tech_stack):
    result = {
        'cves': [], 'total': 0,
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0,
        'high_confidence': 0, 'medium_confidence': 0, 'low_confidence': 0,
        'error': None,
    }
    techs = [t for t in (tech_stack or {}).get('technologies', [])
             if t.get('name', '').strip()]
    if not techs:
        result['error'] = 'No technologies to match'
        return result

    all_cves = []

    # Parallel NVD calls — was sequential loop before
    with futures.ThreadPoolExecutor(max_workers=NVD_MAX_WORKERS) as ex:
        fmap = {ex.submit(_fetch_cves_for_tech, tech): tech for tech in techs}
        for future in futures.as_completed(fmap):
            try:
                all_cves.extend(future.result())
            except Exception:
                logger.error(f"CVE fetch error for {fmap[future].get('name')}", exc_info=True)

    # Deterministic dedup — keep highest-confidence entry per CVE ID
    confidence_rank = {'high': 3, 'medium': 2, 'low': 1}
    seen = {}
    for cve in all_cves:
        cid = cve['id']
        if cid not in seen or (
            confidence_rank.get(cve.get('confidence', 'low'), 1) >
            confidence_rank.get(seen[cid].get('confidence', 'low'), 1)
        ):
            seen[cid] = cve

    unique             = sorted(seen.values(), key=lambda x: x.get('score') or 0, reverse=True)
    result['cves']     = unique
    result['total']    = len(unique)

    for cve in unique:
        sev = cve.get('severity', 'UNKNOWN')
        if   sev == 'CRITICAL': result['critical'] += 1
        elif sev == 'HIGH':     result['high']     += 1
        elif sev == 'MEDIUM':   result['medium']   += 1
        elif sev == 'LOW':      result['low']      += 1
        else:                   result['unknown']  += 1

        conf = cve.get('confidence', 'low')
        if   conf == 'high':   result['high_confidence']   += 1
        elif conf == 'medium': result['medium_confidence'] += 1
        else:                  result['low_confidence']    += 1

    return result


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER
#
# Execution timeline:
#   t=0      phase 1  headers                              ~7s
#   t=7      html fetch                                    ~7s
#   t=14     ┌─ phase 2  tech stack          ~5s ─┐
#            ├─ phase 3  subdomains (5 src)  ~8s  ├── all parallel
#            └─ phase 4  CVEs fires as soon       ┘
#               as phase 2 returns tech list
#   t=~22   done  (vs 2-5 min before)
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(domain, mode='full', session_id=None):
    input_domain = domain
    domain       = normalize_domain(domain)

    is_valid, error = validate_domain(domain)
    if not is_valid:
        return {'error': error, 'input_domain': input_domain}

    result = {
        'input_domain': input_domain,
        'domain':       domain,
        'scanned_at':   datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'mode':         mode,
        'headers':      None,
        'tech_stack':   None,
        'subdomains':   None,
        'cves':         None,
        'risk_score':   None,
    }

    # Phase 1 — must complete first
    result['headers'] = scan_headers(domain, mode=mode)
    if result['headers']['error'] and not result['headers']['ssl_issue']:
        return result

    if mode == 'quick':
        return result

    
    html_content = None
    raw_headers  = None
    try:
        r = requests.get(
            'https://' + domain, timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (VulnWatch Security Scanner)'},
            verify=certifi.where()
        )
        html_content = r.text
        raw_headers  = dict(r.headers)
    except Exception:
        logger.warning(f"Could not fetch HTML for {domain}")

    
    with futures.ThreadPoolExecutor(max_workers=3) as ex:
        f_tech = ex.submit(scan_tech_stack, domain, html_content, raw_headers)
        f_subs = ex.submit(scan_subdomains, domain, session_id)

        tech_stack           = f_tech.result()
        result['tech_stack'] = tech_stack

        f_cves = ex.submit(match_cves, tech_stack)   # starts while f_subs still runs

        subs = f_subs.result()
        result['subdomains'] = subs if (subs and not subs.get('scan_failed')) else {
            'subdomains': [], 'total_found': 0,
            'confidence': 'low', 'scan_failed': True, 'sources_used': [],
        }

        result['cves'] = f_cves.result()
        if not result.get('cves'):
            result['cves'] = {
            'cves': [],
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0,
            'error': None
        }

    result['risk_score'] = calculate_risk_score(
        headers_result=result['headers'],
        cves_result=result['cves'],
        tech_stack=result['tech_stack'],
        subdomains_result=result['subdomains'],
    )

    return result