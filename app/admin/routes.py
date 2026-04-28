from flask import Blueprint, render_template, redirect, url_for, abort
from flask_login import login_required, current_user
from app.db import users_collection, scans_collection
from bson import ObjectId

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required():
    if not current_user.is_authenticated or current_user.role != 'admin':
        abort(403)


@admin_bp.route('/')
@login_required
def dashboard():
    admin_required()

    from app.db import monitor_collection

    monitor_count = monitor_collection.count_documents({'active': True})

    users_count = users_collection.count_documents({})
    scans_count = scans_collection.count_documents({})

    return render_template(
        'admin/dashboard.html',
        users_count=users_count,
        scans_count=scans_count,
        monitor_count=monitor_count
    )


@admin_bp.route('/users')
@login_required
def users():
    admin_required()

    users = list(users_collection.find({}, {'password': 0}))

    return render_template('admin/users.html', users=users)

@admin_bp.route('/delete-user/<user_id>')
@login_required
def delete_user(user_id):
    admin_required()

    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        abort(404)

    if user.get('role') == 'admin':
        abort(403)

    if str(user_id) == current_user.id:
        abort(403)

    users_collection.delete_one({'_id': ObjectId(user_id)})

    return redirect(url_for('admin.users'))


@admin_bp.route('/scans')
@login_required
def scans():
    admin_required()

    users_map = {
        str(u['_id']): u.get('username', 'Unknown')
        for u in users_collection.find({}, {'username': 1})
    }

    scans = list(scans_collection.find().sort('scanned_at', -1).limit(50))

    from datetime import timedelta
    IST = timedelta(hours=5, minutes=30)

    for scan in scans:
        scan['username'] = users_map.get(str(scan.get('user_id')), 'Unknown')

        if scan.get('scanned_at'):
            scan['scanned_at'] = scan['scanned_at'] + IST

    return render_template('admin/scans.html', scans=scans)

@admin_bp.route('/scan/<scan_id>')
@login_required
def view_scan(scan_id):
    admin_required()

    from bson import ObjectId
    from datetime import timedelta
    IST = timedelta(hours=5, minutes=30)

    scan = scans_collection.find_one({'_id': ObjectId(scan_id)})

    if not scan:
        abort(404)

    if scan.get("scanned_at"):
        scan["scanned_at_ist"] = scan["scanned_at"] + IST
        
    # convert _id for template
    scan['_id'] = str(scan['_id'])

    return render_template('admin/view_scan.html', scan=scan)

@admin_bp.route('/monitor')
@login_required
def monitor_domains():
    admin_required()

    from app.db import monitor_collection, users_collection
    from datetime import timedelta

    domains = list(monitor_collection.find().sort('added_at', -1))

    users_map = {
        str(u['_id']): u.get('username', 'Unknown')
        for u in users_collection.find({}, {'username': 1})
    }

    IST = timedelta(hours=5, minutes=30)

    for d in domains:
        d['_id'] = str(d['_id'])
        d['username'] = users_map.get(str(d.get('user_id')), 'Unknown')
        if d.get('added_at'):
            d['added_at'] = d['added_at'] + IST
        else:
            d['added_at'] = None

        if d.get('last_scanned'):
            d['last_scanned'] = d['last_scanned'] + IST
        else:
            d['last_scanned'] = None

        d['status'] = 'active' if d.get('active', False) else 'stopped'

    return render_template('admin/monitor.html', domains=domains)

@admin_bp.route('/monitor/delete/<domain_id>')
@login_required
def delete_monitor_domain(domain_id):
    admin_required()

    from app.db import monitor_collection
    from bson import ObjectId

    monitor_collection.delete_one({'_id': ObjectId(domain_id)})

    return redirect(url_for('admin.monitor_domains'))