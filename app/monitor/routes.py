from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.monitor.models import MonitoredDomain
from app.monitor.scheduler import add_monitor_job, remove_monitor_job, scan_monitored_domain
from app.scanner.engine import normalize_domain, validate_domain
from datetime import timedelta
import threading
import logging

logger = logging.getLogger(__name__)

monitor_bp = Blueprint('monitor', __name__)

IST = timedelta(hours=5, minutes=30)


@monitor_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        domain_input = request.form.get('domain', '').strip()
        email = request.form.get('email', '').strip()

        if not domain_input or not email:
            flash('Domain and email are required.', 'danger')
            return redirect(url_for('monitor.index'))

        domain = normalize_domain(domain_input)
        is_valid, error = validate_domain(domain)
        if not is_valid:
            flash(error, 'danger')
            return redirect(url_for('monitor.index'))

        doc, error = MonitoredDomain.add(
            user_id=current_user.id,
            domain=domain,
            email=email,
            is_admin=(current_user.role == 'admin')
        )

        if error:
            flash(error, 'danger')
            return redirect(url_for('monitor.index'))

        domain_id = str(doc['_id'])

        # Add recurring 24hr scheduler job
        add_monitor_job(
            domain_id=domain_id,
            domain=domain,
            alert_email=email,
            user_id=current_user.id
        )

        # Run first scan immediately in background thread
        t = threading.Thread(
            target=scan_monitored_domain,
            args=[domain_id, domain, email, current_user.id]
        )
        t.daemon = True
        t.start()

        flash(f'Now monitoring {domain}. First scan running in background...', 'success')
        return redirect(url_for('monitor.index'))

    domains = MonitoredDomain.get_by_user(current_user.id)
    for d in domains:
        d['_id'] = str(d['_id'])
        d['last_scanned_ist'] = (d['last_scanned'] + IST) if d.get('last_scanned') else None

    return render_template('monitor/index.html', domains=domains)


@monitor_bp.route('/remove/<domain_id>', methods=['POST'])
@login_required
def remove(domain_id):
    success = MonitoredDomain.remove(domain_id, current_user.id)
    if success:
        remove_monitor_job(domain_id)
        flash('Domain removed from monitoring.', 'info')
    else:
        flash('Domain not found.', 'danger')
    return redirect(url_for('monitor.index'))


@monitor_bp.route('/scan-now/<domain_id>', methods=['POST'])
@login_required
def scan_now(domain_id):
    domain = MonitoredDomain.get_by_id(domain_id)
    if not domain or domain['user_id'] != current_user.id:
        flash('Domain not found.', 'danger')
        return redirect(url_for('monitor.index'))

    t = threading.Thread(
        target=scan_monitored_domain,
        args=[domain_id, domain['domain'], domain['alert_email'], current_user.id]
    )
    t.daemon = True
    t.start()

    flash(f'Scan started for {domain["domain"]}. Refresh in ~60 seconds.', 'info')
    return redirect(url_for('monitor.index'))