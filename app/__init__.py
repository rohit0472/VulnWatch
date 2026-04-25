from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_mail import Mail
from dotenv import load_dotenv
import logging
import os

from app.db import users_collection

load_dotenv()

# Extensions
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
mail = Mail()

import json
 
 
def load_exploit_db():
    """
    Loads exploit_map.json into engine.EXPLOIT_INDEX at startup.
    Called once from create_app() — never called per-request.
    
    exploit_map.json must be in your project root (next to app/ folder).
    If the file doesn't exist, exploit enrichment is silently disabled.
    """
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
    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.scanner.routes import scanner_bp
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    # -------------------------
    # App Configuration
    # -------------------------
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
    app.config['ENV'] = os.getenv('FLASK_ENV', 'development')
    # app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False') == 'True'
    app.config['DEBUG'] = False
    app.config['RATELIMIT_STORAGE_URI'] = os.getenv('RATELIMIT_STORAGE_URI', 'memory://')

    # Session security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

    # Mail configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # -------------------------
    # Security Headers (Talisman)
    # -------------------------
    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
        'style-src': ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', "'unsafe-inline'"],
        'font-src': ["'self'", 'cdnjs.cloudflare.com'],
        'img-src': ["'self'", 'data:'],
    }

    Talisman(
        app,
        force_https=False,  # Set True in production
        strict_transport_security=False,  # Set True in production
        content_security_policy=csp,
        x_content_type_options=True,
        x_xss_protection=True,
        referrer_policy='strict-origin-when-cross-origin'
    )

    # -------------------------
    # Initialize Extensions
    # -------------------------
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)

    # -------------------------
    # User Loader
    # -------------------------
    from app.auth.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.get_by_id(user_id)

    # -------------------------
    # Register Blueprints
    # -------------------------
    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.scanner.routes import scanner_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(scanner_bp, url_prefix='/scanner')

    # -------------------------
    # Logging Setup
    # -------------------------
    if not os.path.exists('logs'):
        os.makedirs('logs')

    logging.basicConfig(
        filename='logs/vulnwatch.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s : %(message)s'
    )

    app.logger.info('VulnWatch started')

    # Start monitoring scheduler
    print("STARTING SCHEDULER...")
    from app.monitor.scheduler import start_scheduler
    start_scheduler()
    from app.monitor.routes import monitor_bp
    app.register_blueprint(monitor_bp, url_prefix='/monitor')

    # from app.api.routes import api_bp
    # app.register_blueprint(api_bp, url_prefix='/api')


    #admin login

    from app.admin.routes import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    load_exploit_db() 

    return app