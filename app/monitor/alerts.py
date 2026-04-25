from flask_mail import Message
from app import mail
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def send_alert_email(to_email, domain, cves):
    try:
        verified = [c for c in cves if c.get('confidence') == 'high']
        possible = [c for c in cves if c.get('confidence') == 'medium']

        if not verified and not possible:
            logger.info(f"No high/medium CVEs for {domain} — skipping alert")
            return False

        def sort_key(c):
            return c.get('score') or 0

        verified = sorted(verified, key=sort_key, reverse=True)
        possible = sorted(possible, key=sort_key, reverse=True)

        parts = []
        if verified: parts.append(f"{len(verified)} Verified")
        if possible: parts.append(f"{len(possible)} Possible")
        subject = f"VulnWatch Alert — {' + '.join(parts)} Vulnerabilities on {domain}"

        def cve_block(cve):
            sev   = cve.get('severity', 'UNKNOWN')
            score = cve.get('score', 'N/A')
            emoji = ("🔴" if sev == "CRITICAL" else
                     "🟠" if sev == "HIGH" else
                     "🟡" if sev == "MEDIUM" else "⚪")
            kev_line     = "  ⚠️  Listed in CISA KEV\n" if cve.get('kev') else ""
            exploit_line = ""

            if cve.get('exploit_available'):
                exploit_urls = cve.get('exploit_urls', [])
                if exploit_urls:
                    first = exploit_urls[0]
                    title = first.get('title', 'Exploit available')
                    url   = first.get('url', '')
                    exploit_line = (
                        f"  🔥 Exploit Available\n"
                        f"     {title}\n"
                        f"     {url}\n"
                    )
                    if len(exploit_urls) > 1:
                        exploit_line += f"     + {len(exploit_urls) - 1} more exploit(s)\n"
                else:
                    exploit_line = "  🔥 Exploit Available\n"

            return (
                f"{emoji} {cve.get('id')}\n"
                f"   Technology : {cve.get('technology')}\n"
                f"   Severity   : {sev}  |  Score: {score}\n"
                f"   NVD Link   : {cve.get('url')}\n"
                f"{kev_line}"
                f"{exploit_line}"
            )

        verified_section = ""
        if verified:
            verified_section = (
                "VERIFIED CVEs  (version-matched, high confidence)\n"
                + "-" * 47 + "\n"
                + "\n".join(cve_block(c) for c in verified[:5])
            )
            if len(verified) > 5:
                verified_section += f"  ... and {len(verified) - 5} more verified CVEs.\n"

        possible_section = ""
        if possible:
            possible_section = (
                "POSSIBLE CVEs  (keyword-matched, may include false positives)\n"
                + "-" * 47 + "\n"
                + "\n".join(cve_block(c) for c in possible[:5])
            )
            if len(possible) > 5:
                possible_section += f"  ... and {len(possible) - 5} more possible CVEs.\n"

        total_exploits = sum(
            1 for c in (verified + possible) if c.get('exploit_available')
        )
        exploit_summary = ""
        if total_exploits > 0:
            exploit_summary = (
                f"\n{total_exploits} CVE(s) above have public exploits available.\n"
                f"Prioritise these for immediate remediation.\n"
            )

        scan_time     = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        dashboard_url = 'https://vulnwatch.in/history'

        body = f"""VulnWatch Security Alert
{"=" * 47}

Target Domain : {domain}
Scan Time     : {scan_time} UTC

New vulnerabilities detected during scheduled monitoring.

Summary
{"-" * 47}
  Verified CVEs (high confidence) : {len(verified)}
  Possible CVEs (keyword-matched) : {len(possible)}
  CVEs with public exploits       : {total_exploits}

{verified_section}
{possible_section}{exploit_summary}
{"=" * 47}

Recommended Actions
{"-" * 47}
  * Prioritize CVEs marked Exploit Available - public PoC exists
  * Verified CVEs are version-matched - act on these immediately
  * Possible CVEs need manual confirmation before remediation
  * Update affected technologies to their latest patched versions

View full report : {dashboard_url}

- VulnWatch Monitoring System
"""

        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)

        logger.info(
            f"Alert sent to {to_email} for {domain} "
            f"({len(verified)} verified, {len(possible)} possible, "
            f"{total_exploits} exploitable)"
        )
        return True

    except Exception:
        logger.error("Failed to send alert email", exc_info=True)
        return False