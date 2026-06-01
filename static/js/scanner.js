/**
 * scanner.js
 *
 * Flow
 * ----
 * 1. User submits the scan form.
 * 2. JS POSTs to /scan — Flask inserts a DB record, fires a background
 *    thread, and immediately returns a redirect to /scanning/<scan_id>.
 *    fetch() follows the redirect and lands on the scanning page HTML.
 *    We grab the scan_id from that URL and start polling.
 *
 * 3. Every 3 s we hit GET /status/<scan_id> (JSON).
 *    • { status: "running" }   → keep spinning
 *    • { status: "completed" } → redirect to /result/<scan_id>
 *    • { status: "failed" }    → show error
 *    • { status: "error" }     → show error
 *
 * This means the Flask worker is NEVER blocked — the browser does all
 * the waiting, and Render never sees a slow request.
 */

(function () {
    'use strict';

    /* ── DOM refs ──────────────────────────────────────────────── */
    var form          = document.getElementById('scanForm');
    var loader        = document.getElementById('loaderSection');
    var resultsDiv    = document.getElementById('resultsSection');
    var loaderHeading = document.getElementById('loaderHeading');
    var progressFill  = document.getElementById('scanProgressFill');
    var stepPills     = document.querySelectorAll('.step-pill');
    var scanBtn       = document.getElementById('scanBtn');
    var domainInput   = document.getElementById('domainInput');

    if (!form) return;

    /* ── Step config ───────────────────────────────────────────── */
    var steps = [
        { label: 'Checking HTTPS & security headers…',        pill: 0 },
        { label: 'Detecting tech stack…',                      pill: 1 },
        { label: 'Discovering subdomains across 5 sources…',  pill: 2 },
        { label: 'Matching CVEs against detected stack…',     pill: 3 },
    ];

    var stepTimer     = null;
    var progressTimer = null;
    var pollTimer     = null;
    var currentStep   = 0;

    /* ── Loader helpers ────────────────────────────────────────── */
    function showLoader() {
        loader.style.display = 'block';
        resultsDiv.innerHTML = '';
        currentStep          = 0;
        loader.scrollIntoView({ behavior: 'smooth', block: 'center' });

        if (scanBtn) {
            scanBtn.disabled  = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning…';
        }

        applyStep(0);

        // Cycle step pills every 8 s to give visual progress feedback
        stepTimer = setInterval(function () {
            currentStep = (currentStep + 1) % steps.length;
            applyStep(currentStep);
        }, 8000);

        // Creep progress bar 0 → 88 % over 80 s (leaves room to snap to 100%)
        animateProgress(0, 88, 80000);
    }

    function applyStep(idx) {
        if (loaderHeading) loaderHeading.textContent = steps[idx].label;
        stepPills.forEach(function (pill) {
            pill.classList.toggle(
                'active',
                parseInt(pill.dataset.step, 10) === steps[idx].pill
            );
        });
    }

    function animateProgress(from, to, durationMs) {
        clearInterval(progressTimer);
        var start = performance.now();
        var range = to - from;
        progressTimer = setInterval(function () {
            var elapsed = performance.now() - start;
            var pct     = from + range * Math.min(elapsed / durationMs, 1);
            if (progressFill) progressFill.style.width = pct + '%';
            if (elapsed >= durationMs) clearInterval(progressTimer);
        }, 200);
    }

    function hideLoader(success) {
        clearInterval(stepTimer);
        clearInterval(progressTimer);
        clearInterval(pollTimer);
        stepTimer = progressTimer = pollTimer = null;

        if (progressFill) progressFill.style.width = '100%';

        setTimeout(function () {
            loader.style.display = 'none';
            if (progressFill) progressFill.style.width = '0%';
        }, success ? 400 : 0);

        if (scanBtn) {
            scanBtn.disabled  = false;
            scanBtn.innerHTML = '<i class="fas fa-search me-2"></i>Scan';
        }
    }

    function showError(msg) {
        hideLoader(false);
        resultsDiv.innerHTML =
            '<div class="alert alert-danger mt-3">' +
            '<i class="fas fa-exclamation-triangle me-2"></i>' +
            msg + '</div>';
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /* ── Polling ───────────────────────────────────────────────── */
    function startPolling(scanId) {
        var statusUrl = '/scanner/status/' + scanId;
        var resultUrl = '/scanner/result/' + scanId;
        var attempts  = 0;
        var maxAttempts = 60; // 60 × 3 s = 3 min ceiling on the client

        pollTimer = setInterval(function () {
            attempts++;
            if (attempts > maxAttempts) {
                showError('Scan is taking longer than expected. ' +
                          'Check History in a few minutes — your result will be saved there.');
                return;
            }

            fetch(statusUrl, { credentials: 'same-origin' })
                .then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                })
                .then(function (data) {
                    if (data.status === 'running') {
                        return; // keep polling
                    }

                    // Terminal states — stop the interval first
                    clearInterval(pollTimer);
                    pollTimer = null;

                    if (data.status === 'completed') {
                        // Snap progress to 100%, then navigate to result page
                        animateProgress(
                            parseFloat(progressFill ? progressFill.style.width : 88),
                            100,
                            400
                        );
                        setTimeout(function () {
                            window.location.href = resultUrl;
                        }, 500);
                    } else {
                        // failed or error
                        showError(data.message || 'Scan failed. Please try again.');
                    }
                })
                .catch(function (err) {
                    // Network blip — don't stop polling, just log
                    console.warn('Poll error (will retry):', err);
                });

        }, 3000); // poll every 3 seconds
    }

    /* ── Form submit ───────────────────────────────────────────── */
    form.addEventListener('submit', function (e) {
        e.preventDefault();

        var domain = domainInput ? domainInput.value.trim() : '';
        if (!domain) return;

        var postUrl = (scanBtn && scanBtn.dataset.action)
            ? scanBtn.dataset.action
            : '/scan';

        showLoader();

        fetch(postUrl, {
            method:      'POST',
            body:        new FormData(form),
            credentials: 'same-origin',
            redirect:    'follow',   // follow the redirect to /scanning/<id>
        })
        .then(function (response) {
            // Auth failure → hard navigate
            if (response.url && response.url.includes('/login')) {
                window.location.href = response.url;
                return null;
            }
            if (!response.ok) throw new Error('Server error ' + response.status);
            return response.url; // final URL after redirect = /scanning/<scan_id>
        })
        .then(function (finalUrl) {
            if (!finalUrl) return;

            // Extract scan_id from the redirected URL  /scanning/<scan_id>
            var match = finalUrl.match(/\/scanning\/([a-f0-9]{24})/);
            if (!match) {
                // Unexpected redirect — just navigate there
                window.location.href = finalUrl;
                return;
            }

            var scanId = match[1];
            startPolling(scanId);
        })
        .catch(function (err) {
            console.error('Scan submit error:', err);
            showError('Could not reach the server. Check your connection and try again.');
        });
    });

})();