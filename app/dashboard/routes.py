from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
import requests
import logging
from datetime import datetime, timezone, timedelta
from app.db import cves_collection
from app.api.models import APIKey

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)

SECURITY_TIPS = [
    "Always use strong, unique passwords for every account.",
    "Enable two-factor authentication wherever possible.",
    "Keep your software and dependencies updated regularly.",
    "Never expose admin panels or dev ports to the public internet.",
    "Regularly audit who has access to your systems.",
    "Use HTTPS everywhere — never serve sensitive data over HTTP.",
    "Back up your data regularly and test your backups.",
    "Monitor your logs — most breaches are visible in logs before damage is done.",
    "Rotate your API keys and secrets periodically.",
    "Assume breach mentality — design systems to limit blast radius.",
]

CACHE_EXPIRY_HOURS = 6


def fetch_from_nist():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    now = datetime.utcnow()
    past = now - timedelta(days=1)

    params = {
        'resultsPerPage': 50,
        'startIndex': 0,
        'pubStartDate': past.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'pubEndDate': now.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
    }

    response = requests.get(url, params=params, timeout=10)
    response.raise_for_status()
    data = response.json()

    cves = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})

        if cve.get('vulnStatus') in ['Rejected', 'REJECTED']:
            continue

        cve_id = cve.get('id', 'N/A')
        descriptions = cve.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d['lang'] == 'en'),
            'No description available'
        )

        if description.startswith('Rejected'):
            continue

        score = None
        severity = 'UNKNOWN'
        metrics = cve.get('metrics', {})

        if metrics.get('cvssMetricV31'):
            cvss = metrics['cvssMetricV31'][0]['cvssData']
            score = cvss.get('baseScore')
            severity = cvss.get('baseSeverity', 'UNKNOWN')
        elif metrics.get('cvssMetricV30'):
            cvss = metrics['cvssMetricV30'][0]['cvssData']
            score = cvss.get('baseScore')
            severity = cvss.get('baseSeverity', 'UNKNOWN')
        elif metrics.get('cvssMetricV2'):
            cvss = metrics['cvssMetricV2'][0]['cvssData']
            score = cvss.get('baseScore')
            severity = 'MEDIUM'

        published = cve.get('published', '')[:10]

        cves.append({
            'id': cve_id,
            'description': description[:150] + '...' if len(description) > 150 else description,
            'score': score,
            'severity': severity,
            'published': published
        })

        if len(cves) >= 50:
            break

    return cves


def get_latest_cves(limit=10):
    try:
        # -------------------------
        # Check MongoDB cache
        # -------------------------
        cache = cves_collection.find_one({'_id': 'dashboard_cache'})

        if cache:
            last_updated = cache.get('last_updated')
            age = (datetime.utcnow() - last_updated).total_seconds()

            if age < CACHE_EXPIRY_HOURS * 3600:
                logger.info("CVEs served from MongoDB cache")
                return cache.get('cves', [])[:limit]

        # -------------------------
        # Cache stale — fetch fresh
        # -------------------------
        logger.info("Fetching fresh CVEs from NIST NVD")
        cves = fetch_from_nist()

        if cves:
            # Update MongoDB cache
            cves_collection.update_one(
                {'_id': 'dashboard_cache'},
                {'$set': {
                    'cves': cves,
                    'last_updated': datetime.utcnow(),
                    'total': len(cves)
                }},
                upsert=True
            )
            logger.info(f"MongoDB cache updated with {len(cves)} CVEs")

        return cves[:limit]

    except Exception:
        logger.error("Failed to get CVEs", exc_info=True)
        # Last resort — return whatever is in MongoDB even if stale
        try:
            cache = cves_collection.find_one({'_id': 'dashboard_cache'})
            if cache:
                logger.info("Serving stale cache as fallback")
                return cache.get('cves', [])[:limit]
        except Exception:
            pass
        return []


def get_security_tip():
    day_of_year = datetime.now(timezone.utc).timetuple().tm_yday
    return SECURITY_TIPS[day_of_year % len(SECURITY_TIPS)]


@dashboard_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    cves = get_latest_cves()
    tip = get_security_tip()
    quick_result = None

    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if domain:
            from app.scanner.engine import run_scan, calculate_risk_score
            quick_result = run_scan(domain, mode='quick')
            if quick_result and quick_result.get('headers'):
                quick_result['risk'] = assess_risk(quick_result['headers'])
                quick_result['risk_score'] = calculate_risk_score(
                    headers_result=quick_result['headers']
                )

    return render_template(
        'dashboard/index.html',
        username=current_user.username,
        role=current_user.role,
        cves=cves,
        tip=tip,
        quick_result=quick_result
    )
def assess_risk(headers_result):
    score = headers_result.get('header_score', 0)
    https = headers_result.get('https', False)
    ssl_issue = headers_result.get('ssl_issue', False)
    missing = headers_result.get('missing_headers', [])

    # Risk level
    if not https or ssl_issue or score == 0:
        risk_level = 'CRITICAL'
        risk_message = 'Critical security misconfiguration detected'
        risk_color = '#f85149'
    elif score < 40:
        risk_level = 'HIGH'
        risk_message = 'High risk — critical security headers missing'
        risk_color = '#f85149'
    elif score < 70:
        risk_level = 'MEDIUM'
        risk_message = 'Medium risk — some security headers missing'
        risk_color = '#d29922'
    elif score < 100:
        risk_level = 'LOW'
        risk_message = 'Low risk — minor security improvements possible'
        risk_color = '#58a6ff'
    else:
        risk_level = 'SECURE'
        risk_message = 'All security headers present'
        risk_color = '#3fb950'

    # Impact explanations per missing header
    HEADER_IMPACTS = {
        'Content-Security-Policy': 'No CSP → Increased XSS risk',
        'Strict-Transport-Security': 'No HSTS → HTTPS downgrade attack possible',
        'X-Frame-Options': 'No X-Frame-Options → Clickjacking risk',
        'X-Content-Type-Options': 'No X-Content-Type-Options → MIME sniffing attacks possible',
        'Referrer-Policy': 'No Referrer-Policy → Sensitive URL data leaked to third parties',
        'Permissions-Policy': 'No Permissions-Policy → Browser features uncontrolled',
    }

    impacts = []
    for header in missing:
        if header in HEADER_IMPACTS:
            impacts.append(HEADER_IMPACTS[header])

    return {
        'level': risk_level,
        'message': risk_message,
        'color': risk_color,
        'impacts': impacts
    }



@dashboard_bp.route('/api-keys', methods=['GET', 'POST'])
@login_required
def api_keys():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate':
            name = request.form.get('name', 'Default').strip()
            key, error = APIKey.generate(current_user.id, name)
            if error:
                flash(error, 'danger')
            else:
                flash(f'API key generated: {key} — Save this now, it won\'t be shown again!', 'success')

        elif action == 'revoke':
            key_id = request.form.get('key_id')
            if APIKey.revoke(key_id, current_user.id):
                flash('API key revoked.', 'info')

        elif action == 'regenerate':
            key_id = request.form.get('key_id')
            new_key, error = APIKey.regenerate(key_id, current_user.id)
            if error:
                flash(error, 'danger')
            else:
                flash(f'New key: {new_key} — Save this now!', 'success')

        return redirect(url_for('dashboard.api_keys'))

    keys = APIKey.get_by_user(current_user.id)
    for k in keys:
        k['_id'] = str(k['_id'])
        if k.get('expires_at'):
            k['expires_at_str'] = k['expires_at'].strftime('%Y-%m-%d')
        if k.get('last_used'):
            k['last_used_str'] = k['last_used'].strftime('%Y-%m-%d %H:%M')
        else:
            k['last_used_str'] = 'Never'

    return render_template('dashboard/api_keys.html', keys=keys)