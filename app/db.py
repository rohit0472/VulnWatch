from pymongo import MongoClient
from dotenv import load_dotenv
import os
import logging

load_dotenv()

logger = logging.getLogger(__name__)

def get_db():
    try:
        client = MongoClient(os.getenv("MONGO_URI"))
        db = client['vulnwatch']
        return db
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise

# Initialize db instance
db = get_db()

# Collections
users_collection = db['users']
scans_collection = db['scans']
monitor_collection = db['monitored_domains']
cves_collection = db['cves']
monitored_domains_collection = db['monitored_domains']
alerts_collection = db['alerts']
audit_logs_collection = db['audit_logs']
api_keys_collection = db['api_keys']

# Create indexes for performance and security
def create_indexes():
    try:
        # Users - email must be unique
        users_collection.create_index('email', unique=True)
        users_collection.create_index('username', unique=True)

        # Scans - fast lookup by domain and user
        scans_collection.create_index('domain')
        scans_collection.create_index('user_id')

        # CVEs - fast lookup by CVE ID
        cves_collection.create_index('cve_id', unique=True)

        # Monitored domains
        monitored_domains_collection.create_index('user_id')
        monitored_domains_collection.create_index('domain')

        # Alerts - for cooldown checking
        alerts_collection.create_index([('domain', 1), ('cve_id', 1)])

        # Audit logs
        audit_logs_collection.create_index('user_id')
        audit_logs_collection.create_index('timestamp')

        # API keys
        api_keys_collection.create_index('key', unique=True)
        api_keys_collection.create_index('user_id')

        logger.info("✅ Database indexes created successfully")
    except Exception as e:
        logger.error(f"Index creation failed: {e}")

create_indexes()