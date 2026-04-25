from datetime import datetime
from bson import ObjectId
from app.db import monitored_domains_collection, alerts_collection
import logging

logger = logging.getLogger(__name__)

MAX_DOMAINS_PER_USER = 5


class MonitoredDomain:

    @staticmethod
    def get_by_user(user_id):
        return list(monitored_domains_collection.find(
            {'user_id': user_id}
        ).sort('added_at', -1))

    @staticmethod
    def get_by_id(domain_id):
        try:
            return monitored_domains_collection.find_one(
                {'_id': ObjectId(domain_id)}
            )
        except Exception:
            return None

    @staticmethod
    def count_by_user(user_id):
        return monitored_domains_collection.count_documents(
            {'user_id': user_id}
        )

    @staticmethod
    def add(user_id, domain, email, is_admin=False):
        # Check limit
        if not is_admin and MonitoredDomain.count_by_user(user_id) >= MAX_DOMAINS_PER_USER:
            return None, f'Maximum {MAX_DOMAINS_PER_USER} monitored domains allowed'

        # Check duplicate
        existing = monitored_domains_collection.find_one({
            'user_id': user_id,
            'domain': domain
        })
        if existing:
            return None, 'Domain already being monitored'

        doc = {
            'user_id': user_id,
            'domain': domain,
            'alert_email': email,
            'added_at': datetime.utcnow(),
            'last_scanned': None,
            'last_scan_result': None,
            'status': 'pending',
            'active': True
        }

        result = monitored_domains_collection.insert_one(doc)
        doc['_id'] = result.inserted_id
        logger.info(f"Domain added to monitoring: {domain}")
        return doc, None

    @staticmethod
    def remove(domain_id, user_id):
        result = monitored_domains_collection.delete_one({
            '_id': ObjectId(domain_id),
            'user_id': user_id
        })
        return result.deleted_count > 0

    @staticmethod
    def update_scan_result(domain_id, scan_result, status='ok'):
        monitored_domains_collection.update_one(
            {'_id': ObjectId(domain_id)},
            {'$set': {
                'last_scanned': datetime.utcnow(),
                'last_scan_result': scan_result,
                'status': status
            }}
        )

    @staticmethod
    def was_alerted_recently(domain, cve_id, cooldown_hours=24):
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=cooldown_hours)
        existing = alerts_collection.find_one({
            'domain': domain,
            'cve_id': cve_id,
            'alerted_at': {'$gte': cutoff}
        })
        return existing is not None

    @staticmethod
    def log_alert(domain, cve_id, user_id):
        alerts_collection.insert_one({
            'domain': domain,
            'cve_id': cve_id,
            'user_id': user_id,
            'alerted_at': datetime.utcnow()
        })

    @staticmethod
    def get_all_active():
        return list(monitored_domains_collection.find({'active': True}))