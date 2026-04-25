from datetime import datetime, timedelta
from app.db import api_keys_collection
from bson import ObjectId
import secrets
import hashlib
import logging

logger = logging.getLogger(__name__)


def hash_key(raw_key):
    return hashlib.sha256(raw_key.encode()).hexdigest()


class APIKey:

    @staticmethod
    def generate(user_id, name='Default'):
        count = api_keys_collection.count_documents({'user_id': user_id})
        if count >= 3:
            return None, 'Maximum 3 API keys allowed'

        raw_key = 'vw_' + secrets.token_hex(24)
        hashed = hash_key(raw_key)

        doc = {
            'user_id': user_id,
            'name': name,
            'key': hashed,
            'key_prefix': raw_key[:12],
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(days=365),
            'last_used': None,
            'is_active': True
        }
        api_keys_collection.insert_one(doc)
        logger.info(f"API key generated for user {user_id}")
        return raw_key, None  # Return raw only once

    @staticmethod
    def get_by_user(user_id):
        return list(api_keys_collection.find(
            {'user_id': user_id}
        ).sort('created_at', -1))

    @staticmethod
    def validate(raw_key):
        hashed = hash_key(raw_key)
        doc = api_keys_collection.find_one({
            'key': hashed,
            'is_active': True
        })
        if not doc:
            return None
        if doc.get('expires_at') and doc['expires_at'] < datetime.utcnow():
            return None
        api_keys_collection.update_one(
            {'_id': doc['_id']},
            {'$set': {'last_used': datetime.utcnow()}}
        )
        return doc

    @staticmethod
    def revoke(key_id, user_id):
        result = api_keys_collection.update_one(
            {'_id': ObjectId(key_id), 'user_id': user_id},
            {'$set': {'is_active': False}}
        )
        return result.modified_count > 0

    @staticmethod
    def regenerate(key_id, user_id):
        raw_key = 'vw_' + secrets.token_hex(24)
        hashed = hash_key(raw_key)
        result = api_keys_collection.update_one(
            {'_id': ObjectId(key_id), 'user_id': user_id},
            {'$set': {
                'key': hashed,
                'key_prefix': raw_key[:12],
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(days=365),
                'is_active': True,
                'last_used': None
            }}
        )
        if result.modified_count > 0:
            return raw_key, None
        return None, 'Key not found'