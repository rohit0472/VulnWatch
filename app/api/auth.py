from functools import wraps
from flask import request, jsonify
from app.api.models import APIKey


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Only accept key from header — never from URL
        key = request.headers.get('X-API-Key')

        if not key:
            return jsonify({
                'error': 'API key required',
                'hint': 'Pass key via X-API-Key header'
            }), 401

        key_doc = APIKey.validate(key)
        if not key_doc:
            return jsonify({'error': 'Invalid or expired API key'}), 403

        request.api_user_id = key_doc['user_id']
        return f(*args, **kwargs)

    return decorated