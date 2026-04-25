from flask import Blueprint, render_template, request, flash, session, jsonify
from flask_login import login_required, current_user
from app.scanner.engine import run_scan
from app.db import scans_collection, audit_logs_collection
from datetime import datetime
import logging
from flask import send_file
from bson import ObjectId
from flask import redirect, url_for

logger = logging.getLogger(__name__)

scanner_bp = Blueprint('scanner', __name__)


@scanner_bp.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    prefill_domain = request.args.get('domain', '')
    result         = None
    scan_id        = None

    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()

        if not domain:
            flash('Please enter a domain.', 'danger')
            return render_template('scanner/scan.html',
                                   result=None, prefill_domain='', scan_id=None)

        # ── Create a DB record so history works even if scan errors ──
        session_id  = str(current_user.id)
        insert_result = scans_collection.insert_one({
            'user_id':      str(current_user.id),
            'domain':       domain,
            'input_domain': domain,
            'status':       'running',
            'created_at':   datetime.utcnow(),
        })
        scan_id = str(insert_result.inserted_id)

        # ── Run scan synchronously ────────────────────────────────────
        # fetch() in scanner.js keeps the loader alive while this blocks.
        # No background thread needed — the browser is waiting via fetch().
        try:
            result = run_scan(domain, mode='full', session_id=session_id)
        except Exception:
            logger.error(f"run_scan raised for {domain}", exc_info=True)
            result = {'error': 'Scan failed due to an internal error. Please try again.'}

        # ── Save result to DB ─────────────────────────────────────────
        if result and not result.get('error'):
            scans_collection.update_one(
                {'_id': ObjectId(scan_id)},
                {'$set': {
                    'status':     'completed',
                    'headers':    result.get('headers'),
                    'tech_stack': result.get('tech_stack'),
                    'subdomains': result.get('subdomains'),
                    'cves':       result.get('cves'),
                    'risk_score': result.get('risk_score'),
                    'scanned_at': datetime.utcnow(),
                }}
            )
            # attach input_domain so template can show it
            result['input_domain'] = domain
        else:
            scans_collection.update_one(
                {'_id': ObjectId(scan_id)},
                {'$set': {'status': 'failed', 'scanned_at': datetime.utcnow()}}
            )

        return render_template('scanner/scan.html',
                               result=result,
                               scan_id=scan_id,
                               prefill_domain=domain)

    # ── GET — show blank form (or pre-filled domain) ─────────────────
    return render_template('scanner/scan.html',
                           result=None,
                           scan_id=None,
                           prefill_domain=prefill_domain)


@scanner_bp.route('/history')
@login_required
def history():
    try:
        scans = list(scans_collection.find(
            {'user_id': str(current_user.id)},
            {
                'domain': 1, 'input_domain': 1, 'scanned_at': 1,
                'cves': 1, 'tech_stack': 1, 'headers': 1,
                'risk_score': 1, 'status': 1, '_id': 1,
            }
        ).sort('scanned_at', -1).limit(20))

        from datetime import timedelta
        IST = timedelta(hours=5, minutes=30)

        for scan in scans:
            scan['_id'] = str(scan['_id'])

            if scan.get('scanned_at'):
                scan['scanned_at'] = scan['scanned_at'] + IST

            cves = scan.get('cves') or {}
            scan['cve_total']    = cves.get('total', 0)
            scan['cve_critical'] = cves.get('critical', 0)
            scan['cve_high']     = cves.get('high', 0)
            scan['cve_verified'] = cves.get('high_confidence', 0)
            scan['cve_possible'] = (cves.get('medium_confidence', 0) +
                                    cves.get('low_confidence', 0))

            tech = scan.get('tech_stack') or {}
            scan['tech_count'] = len(tech.get('technologies', []))

            headers = scan.get('headers') or {}
            scan['grade'] = headers.get('header_grade', 'N/A')

            cves_data = scan.get('cves') or {}
            all_cves  = cves_data.get('cves', [])
            scan['exploit_count'] = sum(1 for c in all_cves if c.get('exploit_available'))

    except Exception:
        logger.error("Failed to fetch scan history", exc_info=True)
        scans = []

    return render_template('scanner/history.html', scans=scans)


@scanner_bp.route('/report/<scan_id>')
@login_required
def download_report(scan_id):
    try:
        scan = scans_collection.find_one({
            '_id':     ObjectId(scan_id),
            'user_id': str(current_user.id),
        })

        if not scan:
            flash('Scan not found.', 'danger')
            return redirect(url_for('scanner.history'))

        from app.reports.generator import generate_report

        if not scan.get('risk_score') and scan.get('headers'):
            from app.scanner.engine import calculate_risk_score
            scan['risk_score'] = calculate_risk_score(
                headers_result=scan['headers'],
                cves_result=scan.get('cves'),
                tech_stack=scan.get('tech_stack'),
            )

        buffer   = generate_report(scan, username=current_user.username)
        filename = (
            f"vulnwatch_{scan.get('domain', 'report')}_"
            f"{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        )

        return send_file(buffer, as_attachment=True,
                         download_name=filename,
                         mimetype='application/pdf')

    except Exception:
        logger.error("PDF generation failed", exc_info=True)
        flash('Failed to generate report.', 'danger')
        return redirect(url_for('scanner.history'))