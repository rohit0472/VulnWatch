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

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    # -------------------------
    # App Configuration
    # -------------------------
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
    app.config['ENV'] = os.getenv('FLASK_ENV', 'development')
    app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False') == 'True'

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

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

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

    return app