from flask import Blueprint, jsonify, request
from app.api.auth import require_api_key
from app.api.models import APIKey
from app.scanner.engine import run_scan, normalize_domain, validate_domain
from app.db import scans_collection, cves_collection
from app.monitor.models import MonitoredDomain
from app.monitor.scheduler import add_monitor_job
from app import limiter
from datetime import datetime
from bson import ObjectId
import validators
import logging

# api page down

from flask import abort

abort(403)



logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)


def serialize(doc):
    if doc and '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc


# -------------------------
# Health Check
# -------------------------
@api_bp.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'version': '1.0',
        'timestamp': datetime.utcnow().isoformat()
    })

# -------------------------
# POST /api/scan
# -------------------------
@api_bp.route('/scan', methods=['POST'])
@require_api_key
@limiter.limit("10 per minute")
def scan():
    data = request.get_json()
    if not data or not data.get('domain'):
        return jsonify({'error': 'domain is required'}), 400

    domain_input = data.get('domain', '').strip()
    mode = data.get('mode', 'full')

    if mode not in ['full', 'quick']:
        return jsonify({'error': 'mode must be full or quick'}), 400

    domain = normalize_domain(domain_input)
    is_valid, error = validate_domain(domain)
    if not is_valid:
        return jsonify({'error': error}), 400

    result = run_scan(domain, mode=mode)

    if result.get('error'):
        return jsonify({'error': result['error']}), 400

    if result.get('headers'):
        from app.scanner.engine import calculate_risk_score
        result['risk_score'] = calculate_risk_score(
            headers_result=result['headers'],
            cves_result=result.get('cves'),
            tech_stack=result.get('tech_stack')
        )

    try:
        scans_collection.insert_one({
            'user_id': request.api_user_id,
            'domain': domain,
            'input_domain': domain_input,
            'scanned_at': datetime.utcnow(),
            'headers': result.get('headers'),
            'tech_stack': result.get('tech_stack'),
            'subdomains': result.get('subdomains'),
            'cves': result.get('cves'),
            'risk_score': result.get('risk_score'),
            'mode': mode,
            'source': 'api'
        })
    except Exception:
        logger.error("Failed to save API scan", exc_info=True)

    return jsonify({
        'domain': domain,
        'scanned_at': datetime.utcnow().isoformat(),
        'mode': mode,
        'risk_score': result.get('risk_score'),
        'headers': result.get('headers'),
        'tech_stack': {
            'technologies': result.get('tech_stack', {}).get('technologies', []),
            'total': len(result.get('tech_stack', {}).get('technologies', []))
        },
        'cves': {
            'total': result.get('cves', {}).get('total', 0),
            'critical': result.get('cves', {}).get('critical', 0),
            'high': result.get('cves', {}).get('high', 0),
            'medium': result.get('cves', {}).get('medium', 0),
            'verified': result.get('cves', {}).get('high_confidence', 0),
            'top_10': result.get('cves', {}).get('cves', [])[:10]
        },
        'subdomains': {
            'total': result.get('subdomains', {}).get('total_found', 0),
            'list': result.get('subdomains', {}).get('subdomains', [])
        }
    })


# -------------------------
# GET /api/results
# -------------------------
@api_bp.route('/results', methods=['GET'])
@require_api_key
def results():
    limit = min(int(request.args.get('limit', 10)), 50)

    scans = list(scans_collection.find(
        {'user_id': request.api_user_id},
        {
            'domain': 1,
            'scanned_at': 1,
            'risk_score': 1,
            'mode': 1,
            '_id': 1
        }
    ).sort('scanned_at', -1).limit(limit))

    for scan in scans:
        scan['_id'] = str(scan['_id'])
        if scan.get('scanned_at'):
            scan['scanned_at'] = scan['scanned_at'].isoformat()

    return jsonify({'total': len(scans), 'scans': scans})


# -------------------------
# GET /api/cves (requires auth)
# -------------------------
@api_bp.route('/cves', methods=['GET'])
@require_api_key
def cves():
    cache = cves_collection.find_one({'_id': 'dashboard_cache'})
    if not cache:
        return jsonify({'error': 'CVE data not available yet'}), 503

    limit = min(int(request.args.get('limit', 10)), 50)
    cve_list = cache.get('cves', [])[:limit]

    return jsonify({
        'total': len(cache.get('cves', [])),
        'last_updated': cache.get('last_updated', '').isoformat() if cache.get('last_updated') else None,
        'cves': cve_list
    })


# -------------------------
# POST /api/monitor
# -------------------------
@api_bp.route('/monitor', methods=['POST'])
@require_api_key
@limiter.limit("10 per minute")
def add_monitor():
    data = request.get_json()
    if not data or not data.get('domain') or not data.get('email'):
        return jsonify({'error': 'domain and email are required'}), 400

    # Validate email
    if not validators.email(data['email']):
        return jsonify({'error': 'Invalid email address'}), 400

    domain = normalize_domain(data['domain'])
    is_valid, error = validate_domain(domain)
    if not is_valid:
        return jsonify({'error': error}), 400

    doc, error = MonitoredDomain.add(
        user_id=request.api_user_id,
        domain=domain,
        email=data['email']
    )

    if error:
        return jsonify({'error': error}), 400

    add_monitor_job(
        domain_id=str(doc['_id']),
        domain=domain,
        alert_email=data['email'],
        user_id=request.api_user_id
    )

    return jsonify({
        'message': f'Now monitoring {domain}',
        'domain': domain,
        'alert_email': data['email'],
        'id': str(doc['_id'])
    }), 201


# -------------------------
# GET /api/monitor
# -------------------------
@api_bp.route('/monitor', methods=['GET'])
@require_api_key
def list_monitors():
    domains = MonitoredDomain.get_by_user(request.api_user_id)
    result = []
    for d in domains:
        result.append({
            'id': str(d['_id']),
            'domain': d['domain'],
            'alert_email': d['alert_email'],
            'status': d.get('status', 'pending'),
            'last_scanned': d['last_scanned'].isoformat() if d.get('last_scanned') else None,
            'added_at': d['added_at'].isoformat() if d.get('added_at') else None,
        })

    return jsonify({'total': len(result), 'monitors': result})