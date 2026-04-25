from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.base import JobLookupError
import logging
import threading
from datetime import datetime
from threading import Semaphore

logger = logging.getLogger(__name__)

scheduler  = BackgroundScheduler()
scan_limiter = Semaphore(1)   # max 1 concurrent monitor scan


def scan_monitored_domain(domain_id, domain, alert_email, user_id):
    # """
    # Runs a full scan for a monitored domain, saves to DB,
    # and sends an alert email if new high/medium CVEs are found.

    # BUG 2 FIX — semaphore now wraps the ENTIRE function body,
    # not just the print statement.

    # BUG 4 FIX — Flask app context is pushed inside the thread
    # so Flask-Mail can send email. Without this, mail.send() raises
    # RuntimeError: working outside of application context, which gets
    # silently swallowed by the except block and no email is ever sent.
    # """
    with scan_limiter:
        # ── Push Flask app context ────────────────────────────────
        # Required for Flask-Mail and any Flask extensions used here.
        # Without this, all mail.send() calls fail silently.
        from app import create_app
        app = create_app()

        with app.app_context():
            try:
                logger.info(f"Monitor scan started: {domain}")

                from app.scanner.engine import run_scan, calculate_risk_score
                from app.monitor.models import MonitoredDomain
                from app.monitor.alerts import send_alert_email
                from app.db import scans_collection

                result = run_scan(domain, mode='full')

                if not result or result.get('error'):
                    logger.warning(f"Scan returned error for {domain}: {result.get('error') if result else 'None'}")
                    MonitoredDomain.update_scan_result(domain_id, None, status='error')
                    return

                # Calculate risk score
                if result.get('headers'):
                    result['risk_score'] = calculate_risk_score(
                        headers_result=result['headers'],
                        cves_result=result.get('cves'),
                        tech_stack=result.get('tech_stack'),
                        subdomains_result=result.get('subdomains')
                    )

                # Save to scan history
                scans_collection.insert_one({
                    'user_id':      user_id,
                    'domain':       domain,
                    'input_domain': domain,
                    'scanned_at':   datetime.utcnow(),
                    'status':       'completed',
                    'headers':      result.get('headers'),
                    'tech_stack':   result.get('tech_stack'),
                    'subdomains':   result.get('subdomains'),
                    'cves':         result.get('cves'),
                    'risk_score':   result.get('risk_score'),
                    'mode':         'monitor',
                })

                cves_result = result.get('cves') or {}
                all_cves    = cves_result.get('cves', [])

                logger.info(f"Total CVEs found for {domain}: {len(all_cves)}")

                # ── BUG 1 FIX — log exactly what was_alerted_recently returns ──
                # Previously: if this function had any bug or stale data,
                # new_cves stayed empty and no email was ever sent.
                new_cves = []
                for cve in all_cves:
                    cve_id = cve.get('id')
                    if not cve_id:
                        continue

                    confidence = cve.get('confidence', 'low')
                    if confidence not in ['high', 'medium']:
                        logger.debug(f"  Skipping {cve_id} — confidence={confidence}")
                        continue

                    recently_alerted = MonitoredDomain.was_alerted_recently(domain, cve_id)
                    logger.info(f"  CVE {cve_id} | confidence={confidence} | recently_alerted={recently_alerted}")

                    if not recently_alerted:
                        new_cves.append(cve)

                logger.info(f"New CVEs to alert for {domain}: {len(new_cves)}")

                # Sort: verified (high confidence) first, then by score descending
                confidence_order = {'high': 0, 'medium': 1, 'low': 2}
                new_cves.sort(key=lambda c: (
                    confidence_order.get(c.get('confidence', 'low'), 2),
                    -(c.get('score') or 0)
                ))

                if new_cves:
                    logger.info(f"Sending alert to {alert_email} for {domain}")
                    sent = send_alert_email(alert_email, domain, new_cves)
                    if sent:
                        logger.info(f"Alert sent successfully to {alert_email}")
                        for cve in new_cves:
                            MonitoredDomain.log_alert(domain, cve.get('id'), user_id)
                    else:
                        logger.error(f"send_alert_email returned False for {domain}")
                else:
                    logger.info(f"No new CVEs to alert for {domain} — skipping email")

                all_cves_list  = cves_result.get('cves', [])
                exploit_count  = sum(1 for c in all_cves_list if c.get('exploit_available'))
 
                MonitoredDomain.update_scan_result(
                    domain_id,
                    {
                        'risk_score':    result.get('risk_score', {}).get('score'),
                        'cve_total':     cves_result.get('total', 0),
                        'verified_cves': cves_result.get('high_confidence', 0),
                        'header_grade':  result.get('headers', {}).get('header_grade'),
                        'exploit_count': exploit_count,   # NEW
                    },
                    status='ok'
                )

                logger.info(f"Monitor scan complete: {domain}")

            except Exception:
                logger.error(f"Monitor scan failed for {domain}", exc_info=True)
                try:
                    from app.monitor.models import MonitoredDomain
                    MonitoredDomain.update_scan_result(domain_id, None, status='error')
                except Exception:
                    pass


def run_scan_thread(domain_id, domain, alert_email, user_id):
    t = threading.Thread(
        target=scan_monitored_domain,
        args=[domain_id, domain, alert_email, user_id]
    )
    t.daemon = True
    t.start()


def add_monitor_job(domain_id, domain, alert_email, user_id):
    job_id = f"monitor_{domain_id}"
    try:
        scheduler.add_job(
            run_scan_thread,
            trigger='interval',
            hours=2,
            id=job_id,
            args=[domain_id, domain, alert_email, user_id],
            replace_existing=True,
            next_run_time=datetime.utcnow(),
            max_instances=1,
            coalesce=True,
            misfire_grace_time=120
        )
        logger.info(f"Monitor job added: {job_id}")
    except Exception as e:
        logger.error(f"Failed to add monitor job: {e}", exc_info=True)
        raise


def remove_monitor_job(domain_id):
    job_id = f"monitor_{domain_id}"
    try:
        scheduler.remove_job(job_id)
        logger.info(f"Monitor job removed: {job_id}")
    except JobLookupError:
        pass
    except Exception:
        logger.error("Failed to remove monitor job", exc_info=True)


def reload_jobs_from_db():
    from app.monitor.models import MonitoredDomain
    domains = MonitoredDomain.get_all_active()
    for d in domains:
        add_monitor_job(
            str(d['_id']),
            d['domain'],
            d['alert_email'],
            d['user_id']
        )
    logger.info(f"Reloaded {len(domains)} monitor jobs from DB")


def start_scheduler():
    logger.info("Starting APScheduler...")
    if not scheduler.running:
        scheduler.start()
        reload_jobs_from_db()
        logger.info("APScheduler started successfully")