from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_mail import Mail
from dotenv import load_dotenv
import logging
import json
import os

from app.db import users_collection

load_dotenv()

login_manager = LoginManager()
csrf          = CSRFProtect()
limiter       = Limiter(key_func=get_remote_address)
mail          = Mail()


def load_exploit_db():
    from app.scanner import engine
    path = os.path.join(os.path.dirname(__file__), '..', 'exploit_map.json')
    if not os.path.exists(path):
        print("[VulnWatch] exploit_map.json not found — exploit enrichment disabled")
        return
    try:
        with open(path, 'r') as f:
            engine.EXPLOIT_INDEX = json.load(f)
        print(f"[VulnWatch] Exploit-DB loaded — {len(engine.EXPLOIT_INDEX)} CVEs indexed")
    except Exception as e:
        print(f"[VulnWatch] Failed to load exploit_map.json: {e}")


def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    # ── Configuration ─────────────────────────────────────────────────
    app.config['SECRET_KEY']               = os.getenv('FLASK_SECRET_KEY')
    app.config['ENV']                      = os.getenv('FLASK_ENV', 'production')
    app.config['DEBUG']                    = False
    app.config['RATELIMIT_STORAGE_URI']    = os.getenv('RATELIMIT_STORAGE_URI', 'memory://')

    # Session security
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE']  = 'Lax'
    # FIX 3 — enable secure cookies on Render (always HTTPS)
    app.config['SESSION_COOKIE_SECURE']    = os.getenv('FLASK_ENV', 'production') == 'production'
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600

    # Mail
    app.config['MAIL_SERVER']         = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT']           = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS']        = True
    app.config['MAIL_USERNAME']       = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD']       = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # ── Security Headers ───────────────────────────────────────────────
    csp = {
        'default-src': ["'self'"],
        'script-src':  ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
        'style-src':   ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', "'unsafe-inline'"],
        'font-src':    ["'self'", 'cdnjs.cloudflare.com'],
        'img-src':     ["'self'", 'data:'],
    }
    Talisman(
        app,
        force_https=False,
        strict_transport_security=False,
        content_security_policy=csp,
        x_content_type_options=True,
        x_xss_protection=True,
        referrer_policy='strict-origin-when-cross-origin'
    )

    # ── Extensions ────────────────────────────────────────────────────
    login_manager.init_app(app)
    login_manager.login_view            = 'auth.login'
    login_manager.login_message         = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)

    # ── User Loader ───────────────────────────────────────────────────
    from app.auth.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.get_by_id(user_id)

    # ── Blueprints ────────────────────────────────────────────────────
    from app.auth.routes      import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.scanner.routes   import scanner_bp
    from app.monitor.routes   import monitor_bp
    from app.admin.routes     import admin_bp

    app.register_blueprint(auth_bp,      url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(scanner_bp,   url_prefix='/scanner')
    app.register_blueprint(monitor_bp,   url_prefix='/monitor')
    app.register_blueprint(admin_bp,     url_prefix='/admin')

    from flask import redirect, url_for
    from flask_login import current_user

    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))

    # ── Logging ───────────────────────────────────────────────────────
    # FIX 1 — Render filesystem is read-only, log to stdout instead of file
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s : %(message)s'
        # No filename= here — logs go to stdout which Render captures
    )
    app.logger.info('VulnWatch started')

    # ── Scheduler ────────────────────────────────────────────────────
    # FIX 2 — only start scheduler in the main worker process,
    # not in every gunicorn worker. Render sets WEB_CONCURRENCY
    # for multiple workers — we check WERKZEUG_RUN_MAIN or a custom flag.
    _is_main_process = (
        os.environ.get('WERKZEUG_RUN_MAIN') == 'true'   # flask dev server reloader
        or os.environ.get('SCHEDULER_STARTED') is None   # first worker on gunicorn
    )
    if _is_main_process:
        os.environ['SCHEDULER_STARTED'] = '1'
        print("STARTING SCHEDULER...")
        from app.monitor.scheduler import start_scheduler
        start_scheduler()

    load_exploit_db()

    return app