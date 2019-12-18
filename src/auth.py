import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from werkzeug.security import check_password_hash, generate_password_hash

from src.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/check', methods=['POST'])
def check_authenticated():
    if request.method == 'POST':
        user_id = session.get('admin_id') or session.get(
            'vendor_id') or session.get('customer_id')

        if user_id is not None:
            return jsonify(status="200", token=user_id)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@bp.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']
        userType = data['userType']
        db = get_db()

        if userType == 'admin':
            if not email:
                return jsonify(status="400", message="Email is required")
            elif not password:
                return jsonify(status="400", message="Password is required")
            elif db.execute('SELECT id FROM admin WHERE email = ?', (email,)).fetchone() is not None:
                return jsonify(status="409", message="{} is already registered".format(email))
            else:
                db.execute('INSERT INTO admin (email, password) VALUES (?, ?)',
                           (email, generate_password_hash(password)))
                db.commit()
                return jsonify(status="200", message="Admin {} successfully created".format(email))
        elif userType == 'vendor':
            if not email:
                return jsonify(status="400", message="Email is required")
            elif not password:
                return jsonify(status="400", message="Password is required")
            elif db.execute('SELECT id FROM vendor WHERE email = ?', (email,)).fetchone() is not None:
                return jsonify(status="409", message="{} is already registered".format(email))
            else:
                db.execute('INSERT INTO vendor (email, password) VALUES (?, ?)',
                           (email, generate_password_hash(password)))
                db.commit()
                return jsonify(status="200", message="Vendor {} successfully created".format(email))
        elif userType == 'customer':
            vendor_id = data['vendor_id']
            if not email:
                return jsonify(status="400", message="Email is required")
            elif not password:
                return jsonify(status="400", message="Password is required")
            elif not vendor_id:
                return jsonify(status="400", message="Vendor ID is required")
            elif db.execute('SELECT id FROM customer WHERE email = ?', (email,)).fetchone() is not None:
                return jsonify(status="409", message="{} is already registered".format(email))
            else:
                db.execute('INSERT INTO customer (email, password) VALUES (?, ?)',
                           (email, generate_password_hash(password)))
                db.commit()
                return jsonify(status="200", message="Customer {} successfully created".format(email))

    return jsonify(status="500", message="Something went wrong.")


@bp.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']
        userType = data['userType']
        db = get_db()

        if userType == 'admin':
            admin = db.execute(
                'SELECT * FROM admin WHERE email = ?', (email,)).fetchone()

            if admin is None:
                return jsonify(status="400", message="Incorrect Email or Password")
            elif not check_password_hash(admin['password'], password):
                return jsonify(status="400", message="Incorrect Email or Password")
            else:
                session.clear()
                session['admin_id'] = 'admin' + str(admin['id'])
                return jsonify(status="200", message="Admin {} logged in.".format(admin['email']), token='admin'+str(admin['id']))
        elif userType == 'vendor':
            vendor = db.execute(
                'SELECT * FROM vendor WHERE email = ?', (email,)).fetchone()

            if vendor is None:
                return jsonify(status="400", message="Incorrect Email or Password")
            elif not check_password_hash(vendor['password'], password):
                return jsonify(status="400", message="Incorrect Email or Password")
            else:
                session.clear()
                session['vendor_id'] = 'vendor' + str(vendor['id'])
                return jsonify(status="200", message="Vendor {} logged in.".format(vendor['email']), token='vendor'+str(vendor['id']))
        elif userType == 'customer':
            customer = db.execute(
                'SELECT * FROM customer WHERE email = ?', (email,)).fetchone()

            if customer is None:
                return jsonify(status="400", message="Incorrect Email or Password")
            elif not check_password_hash(customer['password'], password):
                return jsonify(status="400", message="Incorrect Email or Password")
            else:
                session.clear()
                session['customer_id'] = 'customer' + str(customer['id'])
                return jsonify(status="200", message="Vendor {} logged in.".format(customer['email']), token='customer'+str(customer['id']))

    return jsonify(status="500", message="Something went wrong.")
