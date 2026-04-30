from datetime import datetime, timedelta
import logging
import os
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

logger = logging.getLogger(__name__)


def send_alert_email(to_email, domain, cves):
    try:
        verified = sorted(
            [c for c in cves if c.get('confidence') == 'high'],
            key=lambda c: c.get('score') or 0, reverse=True
        )
        possible = sorted(
            [c for c in cves if c.get('confidence') == 'medium'],
            key=lambda c: c.get('score') or 0, reverse=True
        )

        if not verified and not possible:
            logger.info(f"No alertable CVEs for {domain} — skipping")
            return False

        verified_exploits = sum(1 for c in verified if c.get('exploit_available'))
        possible_exploits = sum(1 for c in possible if c.get('exploit_available'))
        total_exploits    = verified_exploits + possible_exploits

        subject_parts = []
        if verified:
            subject_parts.append(f"{len(verified)} Verified CVEs")
        if possible:
            subject_parts.append(f"{len(possible)} Possible CVEs")
        if total_exploits:
            subject_parts.append(f"{total_exploits} Exploit(s) Available")

        subject = f"VulnWatch Alert — {domain} — {' | '.join(subject_parts)}"

        def cve_block(cve, is_verified):
            sev   = cve.get('severity', 'UNKNOWN')
            score = cve.get('score', 'N/A')
            emoji = ("🔴" if sev == "CRITICAL" else
                     "🟠" if sev == "HIGH"     else
                     "🟡" if sev == "MEDIUM"   else "⚪")
            kev_line = "  ⚠️  Listed in CISA KEV\n" if cve.get('kev') else ""

            exploit_line = ""
            if cve.get('exploit_available'):
                urls = cve.get('exploit_urls', [])
                label = "🔥 Exploit Available" if is_verified else "⚠️  Possible Exploit (unconfirmed version)"
                if urls:
                    first = urls[0]
                    exploit_line = (
                        f"  {label}\n"
                        f"     {first.get('title', '')}\n"
                        f"     {first.get('url', '')}\n"
                    )
                    if len(urls) > 1:
                        exploit_line += f"     + {len(urls)-1} more exploit(s)\n"
                else:
                    exploit_line = f"  {label}\n"

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
                "Action Required — patch or mitigate these immediately\n"
                + "-" * 47 + "\n"
                + "\n".join(cve_block(c, True) for c in verified[:5])
            )
            if len(verified) > 5:
                verified_section += f"  ... and {len(verified)-5} more verified CVEs in dashboard.\n"

        possible_section = ""
        if possible:
            possible_section = (
                "POSSIBLE CVEs  (keyword-matched, version unknown)\n"
                "Investigation Recommended — confirm before acting\n"
                + "-" * 47 + "\n"
                + "\n".join(cve_block(c, False) for c in possible[:5])
            )
            if len(possible) > 5:
                possible_section += f"  ... and {len(possible)-5} more possible CVEs in dashboard.\n"

        exploit_summary = ""
        if total_exploits:
            lines = []
            if verified_exploits:
                lines.append(f"  {verified_exploits} verified CVE(s) have confirmed public exploits — act immediately.")
            if possible_exploits:
                lines.append(f"  {possible_exploits} possible CVE(s) may have related exploits — investigate.")
            exploit_summary = "\nExploit Summary\n" + "-"*47 + "\n" + "\n".join(lines) + "\n"

        IST = timedelta(hours=5, minutes=30)
        scan_time = (datetime.utcnow() + IST).strftime('%Y-%m-%d %H:%M IST')
        dashboard_url = 'https://vulnwatch-p7vd.onrender.com/scanner/history'

        body = f"""VulnWatch Security Alert
{"=" * 47}

Target Domain : {domain}
Scan Time     : {scan_time}

New vulnerabilities detected during scheduled monitoring.

Summary
{"-" * 47}
  Verified CVEs (high confidence) : {len(verified)}
  Possible CVEs (keyword-matched)  : {len(possible)}
  CVEs with public exploits        : {total_exploits}

{verified_section}
{possible_section}{exploit_summary}
{"=" * 47}

Recommended Actions
{"-" * 47}
  * Verified CVEs are version-matched — act on these first
  * Possible CVEs need manual version confirmation before remediation
  * CVEs marked with exploits have publicly available attack code
  * Update affected technologies to their latest patched versions

View full report : {dashboard_url}

- VulnWatch Monitoring System

Note: Possible CVEs are keyword-based matches and may include
false positives. Always verify before taking action.
"""

        # ── Brevo API ─────────────────────────────────────────────────────
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = os.environ.get("BREVO_API_KEY")

        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": to_email}],
            sender={
                "email": os.environ.get("BREVO_SENDER_EMAIL"),
                "name": "VulnWatch"
            },
            subject=subject,
            text_content=body
        )

        api_instance.send_transac_email(send_smtp_email)
        logger.info(
            f"Alert sent to {to_email} for {domain} "
            f"({len(verified)} verified, {len(possible)} possible, "
            f"{total_exploits} exploitable)"
        )
        return True

    except ApiException as e:
        logger.error(f"Brevo API error sending to {to_email}: {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Failed to send alert email to {to_email}: {e}", exc_info=True)
        return False