from flask_login import UserMixin
from bson import ObjectId
import bcrypt
import re
from datetime import datetime
from pymongo.errors import DuplicateKeyError
from app.db import users_collection, audit_logs_collection
import logging
import traceback

logger = logging.getLogger(__name__)


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.role = user_data.get('role', 'user')
        self.created_at = user_data.get('created_at', datetime.utcnow())
        self._is_active = user_data.get('is_active', True)

    # -------------------------
    # Flask-Login required
    # -------------------------
    def get_id(self):
        return self.id

    @property
    def is_active(self):
        return self._is_active

    # -------------------------
    # Normalize helper
    # -------------------------
    @staticmethod
    def normalize(value):
        return value.lower().strip()

    # -------------------------
    # Input Validation
    # -------------------------
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False
        domain = email.split('@')[1]
        if domain in ['localhost', '127.0.0.1'] or domain.replace('.', '').isdigit():
            return False
        return True

    @staticmethod
    def validate_username(username):
        pattern = r'^[a-zA-Z0-9_]{3,30}$'
        return re.match(pattern, username) is not None

    @staticmethod
    def validate_password(password):
        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters")
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        return errors

    # -------------------------
    # Password methods
    # -------------------------
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                self.password_hash.encode('utf-8')
            )
        except Exception:
            logger.error("check_password failed", exc_info=True)
            return False

    # -------------------------
    # Fetch methods
    # -------------------------
    @staticmethod
    def get_by_id(user_id):
        try:
            user_data = users_collection.find_one({'_id': ObjectId(user_id)})
            return User(user_data) if user_data else None
        except Exception:
            logger.error("get_by_id failed", exc_info=True)
            return None

    @staticmethod
    def get_by_email(email):
        try:
            user_data = users_collection.find_one(
                {'email': User.normalize(email)}
            )
            return User(user_data) if user_data else None
        except Exception:
            logger.error("get_by_email failed", exc_info=True)
            return None

    @staticmethod
    def get_by_username(username):
        try:
            user_data = users_collection.find_one(
                {'username': User.normalize(username)}
            )
            return User(user_data) if user_data else None
        except Exception:
            logger.error("get_by_username failed", exc_info=True)
            return None

    # -------------------------
    # Create user
    # -------------------------
    @staticmethod
    def create(username, email, password):
        if not User.validate_email(email):
            return None, "Invalid email format"

        if not User.validate_username(username):
            return None, "Username must be 3-30 characters, letters/numbers/underscores only"

        password_errors = User.validate_password(password)
        if password_errors:
            return None, password_errors[0]

        user_data = {
            'username': User.normalize(username),
            'email': User.normalize(email),
            'password_hash': User.hash_password(password),
            'role': 'user',
            'is_active': True,
            'created_at': datetime.utcnow(),
            'monitored_domains_count': 0
        }

        try:
            result = users_collection.insert_one(user_data)
            
            user_data['_id'] = result.inserted_id

            
            audit_logs_collection.insert_one({
                'action': 'user_created',
                'user_id': str(result.inserted_id),
                'username': user_data['username'],
                'timestamp': datetime.utcnow(),
                'ip': None
            })
            

            logger.info("New user created successfully")
            return User(user_data), None

        except DuplicateKeyError:
            logger.warning("Duplicate user registration attempt")
            return None, "Email or username already exists"

        except Exception as e:
            logger.error("User creation failed", exc_info=True)
            return None, "Something went wrong. Please try again"

    # -------------------------
    # Audit log helper
    # -------------------------
    @staticmethod
    def log_action(action, user_id, ip=None, details=None):
        try:
            audit_logs_collection.insert_one({
                'action': action,
                'user_id': user_id,
                'ip': ip,
                'details': details,
                'timestamp': datetime.utcnow()
            })
        except Exception as e:
            logger.error("Audit log failed", exc_info=True)
            print(f"[DEBUG] Audit log error: {e}")

    # -------------------------
    # Helpers
    # -------------------------
    def is_admin(self):
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username}>'