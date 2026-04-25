from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from app.auth.models import User
from app.db import audit_logs_collection
from app import limiter
import logging
import time

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


# -------------------------
# Helper: Get Real IP
# -------------------------
def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)


# -------------------------
# Brute Force Tracking
# -------------------------
def get_failed_attempts(ip):
    cutoff = datetime.utcnow() - timedelta(minutes=15)
    return audit_logs_collection.count_documents({
        'action': 'login_failed',
        'ip': ip,
        'timestamp': {'$gte': cutoff}
    })

def is_locked_out(ip):
    return get_failed_attempts(ip) >= 5


# -------------------------
# Register
# -------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    username = ''
    email = ''

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('auth/register.html',
    username=username,
    email=email
)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html',
    username=username,
    email=email
)

        
        user, error = User.create(username, email, password)
        
        if error:
            flash(error, 'danger')
            return render_template('auth/register.html',
    username=username,
    email=email
)

        User.log_action(
            action='user_registered',
            user_id=user.id,
            ip=get_ip()
        )

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html',
    username=username,
    email=email
)


# -------------------------
# Login
# -------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        ip = get_ip()

        # Check lockout first
        if is_locked_out(ip):
            flash('Too many failed attempts. Try again in 15 minutes.', 'danger')
            logger.warning("Locked out login attempt blocked")
            return render_template('auth/login.html')

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if not all([email, password]):
            flash('All fields are required.', 'danger')
            return render_template('auth/login.html')

        user = User.get_by_email(email)

        if not user or not user.check_password(password):
            # Add 1 second delay to slow down brute force
            time.sleep(1)

            User.log_action(
                action='login_failed',
                user_id=user.id if user else 'unknown',
                ip=ip,
                details={'reason': 'invalid_credentials'}
            )

            attempts_left = max(0, 5 - get_failed_attempts(ip))

            if attempts_left == 0:
                flash('Too many failed attempts. Try again in 15 minutes.', 'danger')
            else:
                flash('Invalid email or password.', 'danger')

            return render_template('auth/login.html')

        if not user.is_active:
            flash('Your account has been deactivated. Contact support.', 'danger')
            return render_template('auth/login.html')

        # Successful login
        login_user(user, remember=remember)

        User.log_action(
            action='login_success',
            user_id=user.id,
            ip=ip
        )

        logger.info("User logged in successfully")

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html')


# -------------------------
# Logout
# -------------------------
@auth_bp.route('/logout')
@login_required
def logout():
    User.log_action(
        action='logout',
        user_id=current_user.id,
        ip=get_ip()
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))