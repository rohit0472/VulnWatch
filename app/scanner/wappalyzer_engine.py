import json
import re
import os
import logging

logger = logging.getLogger(__name__)

# -------------------------
# Load Wappalyzer patterns
# -------------------------
TECH_DB = {}

def load_tech_db():
    global TECH_DB
    if TECH_DB:
        return TECH_DB

    path = os.path.join(os.path.dirname(__file__), 'wappalyzer', 'technologies.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            TECH_DB = json.load(f)
        logger.info(f"Loaded {len(TECH_DB)} technologies from Wappalyzer DB")
    except Exception:
        logger.error("Failed to load Wappalyzer DB", exc_info=True)
        TECH_DB = {}

    return TECH_DB


# -------------------------
# Pattern matcher
# -------------------------
def match_pattern(pattern_str, text):
    """
    Wappalyzer patterns look like:
    "WordPress\\;version:\\1"
    Split on \\; to get regex and version group
    """
    if not text or not pattern_str:
        return None, None

    parts = pattern_str.split('\\;')
    regex_str = parts[0]
    version_template = None

    for part in parts[1:]:
        if part.startswith('version:'):
            version_template = part.replace('version:', '').strip()

    try:
        match = re.search(regex_str, text, re.IGNORECASE)
        if match:
            version = None
            if version_template:
                version = version_template
                for i, group in enumerate(match.groups(), 1):
                    if group:
                        version = version.replace(f'\\{i}', group)
                    else:
                        version = version.replace(f'\\{i}', '')
                version = re.sub(r'\\d', '', version).strip()
                version = re.sub(r'\\+', '', version).strip()
                version = version.strip('?').strip()
                if not version or not any(c.isdigit() for c in version):
                    version = None
            return True, version
    except re.error:
        pass

    return None, None


# -------------------------
# Main Wappalyzer scan
# -------------------------
def wappalyzer_scan(headers=None, html=None, url=None):
    db = load_tech_db()
    detected = {}

    headers = headers or {}
    html = html or ''
    url = url or ''

    for tech_name, tech_data in db.items():
        matched = False
        version = None

        # -------------------------
        # Check headers
        # -------------------------
        tech_headers = tech_data.get('headers', {})
        for header_name, pattern in tech_headers.items():
            header_value = headers.get(header_name, '')
            if not header_value:
                # Try case-insensitive header lookup
                for k, v in headers.items():
                    if k.lower() == header_name.lower():
                        header_value = v
                        break

            if header_value:
                if isinstance(pattern, list):
                    for p in pattern:
                        found, v = match_pattern(p, header_value)
                        if found:
                            matched = True
                            version = v
                            break
                else:
                    found, v = match_pattern(pattern, header_value)
                    if found:
                        matched = True
                        version = v

        # -------------------------
        # Check HTML
        # -------------------------
        if not matched and html:
            html_patterns = tech_data.get('html', [])
            if isinstance(html_patterns, str):
                html_patterns = [html_patterns]

            for pattern in html_patterns:
                found, v = match_pattern(pattern, html)
                if found:
                    matched = True
                    version = v or version
                    break

        # -------------------------
        # Check script src
        # -------------------------
        if not matched and html:
            script_patterns = tech_data.get('scriptSrc', [])
            if isinstance(script_patterns, str):
                script_patterns = [script_patterns]

            for pattern in script_patterns:
                found, v = match_pattern(pattern, html)
                if found:
                    matched = True
                    version = v or version
                    break

        # -------------------------
        # Check URL
        # -------------------------
        if not matched and url:
            url_patterns = tech_data.get('url', [])
            if isinstance(url_patterns, str):
                url_patterns = [url_patterns]

            for pattern in url_patterns:
                found, v = match_pattern(pattern, url)
                if found:
                    matched = True
                    version = v or version
                    break

        if matched:
            categories = []
            cats = tech_data.get('cats', [])
            detected[tech_name] = {
                'name': tech_name,
                'version': version,
                'categories': cats,
            }

    return detected