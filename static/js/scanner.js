/**
 * scanner.js
 *
 * ROOT CAUSE OF THE BLANK SCREEN (now fixed in routes.py):
 *   The old route spawned a background thread and returned immediately
 *   with status='running' and NO result. fetch() received that empty
 *   page, swapped it in, and showed nothing. The actual scan result
 *   was written to MongoDB 20 seconds later with nobody watching.
 *
 * HOW IT WORKS NOW:
 *   routes.py runs the scan synchronously — it blocks until done.
 *   fetch() waits the full 20-40s, then receives a page with real results.
 *   The loader stays visible the entire time because the page never navigates.
 *   When fetch resolves we extract #resultsSection and swap it in.
 */

(function () {
    'use strict';

    /* ── DOM refs ─────────────────────────────────────────────── */
    var form          = document.getElementById('scanForm');
    var loader        = document.getElementById('loaderSection');
    var resultsDiv    = document.getElementById('resultsSection');
    var loaderHeading = document.getElementById('loaderHeading');
    var progressFill  = document.getElementById('scanProgressFill');
    var stepPills     = document.querySelectorAll('.step-pill');
    var scanBtn       = document.getElementById('scanBtn');
    var domainInput   = document.getElementById('domainInput');

    if (!form) return;

    /* ── Step config ──────────────────────────────────────────── */
    var steps = [
        { label: 'Checking HTTPS & security headers…',         pill: 0 },
        { label: 'Detecting tech stack…',                       pill: 1 },
        { label: 'Discovering subdomains across 5 sources…',   pill: 2 },
        { label: 'Matching CVEs against detected stack…',      pill: 3 },
    ];

    var stepTimer     = null;
    var progressTimer = null;
    var currentStep   = 0;

    /* ── Loader ───────────────────────────────────────────────── */
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

        // Cycle step pills every 8 seconds
        stepTimer = setInterval(function () {
            currentStep = (currentStep + 1) % steps.length;
            applyStep(currentStep);
        }, 8000);

        // Creep progress bar 0 → 90% over 35 seconds
        // (leaves room to snap to 100% on completion)
        animateProgress(0, 90, 35000);
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
        }, 100);
    }

    function hideLoader(success) {
        clearInterval(stepTimer);
        clearInterval(progressTimer);
        stepTimer = progressTimer = null;

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

    /* ── Form submit ──────────────────────────────────────────── */
    form.addEventListener('submit', function (e) {
        e.preventDefault(); // stop browser navigation — loader must stay alive

        var domain = domainInput ? domainInput.value.trim() : '';
        if (!domain) return;

        // Build POST url from button's data-action (set by Jinja url_for)
        var postUrl = (scanBtn && scanBtn.dataset.action)
            ? scanBtn.dataset.action
            : window.location.href;

        showLoader();

        fetch(postUrl, {
            method:      'POST',
            body:        new FormData(form),
            credentials: 'same-origin',
        })
        .then(function (response) {
            // Flask may redirect on auth failure — detect that
            if (response.redirected) {
                window.location.href = response.url;
                return null;
            }
            if (!response.ok) {
                throw new Error('Server error ' + response.status);
            }
            return response.text();
        })
        .then(function (html) {
            if (!html) return; // handled redirect above

            var doc        = new DOMParser().parseFromString(html, 'text/html');
            var newResults = doc.getElementById('resultsSection');

            hideLoader(true);

            if (newResults && newResults.innerHTML.trim()) {
                resultsDiv.innerHTML = newResults.innerHTML;
                resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                // resultsSection was empty — scan returned an error page
                showError('Scan completed but no results were returned. Please try again.');
            }
        })
        .catch(function (err) {
            console.error('Scan error:', err);
            showError(
                'Could not reach the server. Check your connection and try again.'
            );
        });
    });

})();