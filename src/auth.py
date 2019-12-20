import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from werkzeug.security import check_password_hash, generate_password_hash

from src.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

authenticated = []


@bp.route('/check', methods=['POST'])
def check_authenticated():
    if request.method == 'POST':
        data = request.get_json()
        token = data['token']
        userType = token[0:-1]
        db = get_db()

        if token in authenticated:
            if userType == 'admin':
                admin = db.execute(
                    'SELECT * FROM admin WHERE id = ?', (token[-1],)).fetchone()

                if admin is None:
                    return jsonify(status="400", message="Unauthenticated")
                else:
                    return jsonify(status="200", colors=[admin['primary_color'], admin['secondary_color'], admin['accent']], token=token)
            elif userType == 'vendor':
                vendor = db.execute(
                    'SELECT * FROM vendor WHERE id = ?', (token[-1],)).fetchone()

                if vendor is None:
                    return jsonify(status="400", message="Unauthenticated")
                else:
                    return jsonify(status="200", colors=[vendor['primary_color'], vendor['secondary_color'], vendor['accent']], token=token)
            elif userType == 'customer':
                customer = db.execute(
                    'SELECT * FROM customer WHERE id = ?', (token[-1],)).fetchone()

                if customer is None:
                    return jsonify(status="400", message="Unauthenticated")
                else:
                    return jsonify(status="200", colors=[customer['primary_color'], customer['secondary_color'], customer['accent']], token=token)
        else:
            return jsonify(status="403")

    return jsonify(status="500", message="Something went wrong")


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@bp.route('/changetheme', methods=['POST'])
def change_theme():
    if request.method == 'POST':
        data = request.get_json()
        user_id = data['user_id']
        userType = data['userType']
        primary_color = data['primary_color']
        secondary_color = data['secondary_color']
        accent = data['accent']
        db = get_db()

        if userType == 'admin':
            admin = db.execute(
                'SELECT * FROM admin WHERE id = ?', (user_id[-1],)).fetchone()

            if admin is None:
                return jsonify(status="400", message="An error occurred while changing theme for user")
            else:
                db.execute('UPDATE admin set primary_color = ?, secondary_color = ?, accent = ? where id = ?',
                           (primary_color, secondary_color, accent, user_id[-1]))
                db.commit()
                return jsonify(status="200", message="Theme successfully changed.", colors=[primary_color, secondary_color, accent])
        elif userType == 'vendor':
            vendor = db.execute(
                'SELECT * FROM vendor WHERE id = ?', (user_id[-1],)).fetchone()

            if vendor is None:
                return jsonify(status="400", message="An error occurred while changing theme for user")
            else:
                db.execute('UPDATE vendor set primary_color = ?, secondary_color = ?, accent = ? where id = ?',
                           (primary_color, secondary_color, accent, user_id[-1]))
                db.commit()
                return jsonify(status="200", message="Theme successfully changed.", colors=[primary_color, secondary_color, accent])
        elif userType == 'customer':
            customer = db.execute(
                'SELECT * FROM customer WHERE id = ?', (user_id[-1],)).fetchone()

            if customer is None:
                return jsonify(status="400", message="An error occurred while changing theme for user")
            else:
                db.execute('UPDATE customer set primary_color = ?, secondary_color = ?, accent = ? where id = ?',
                           (primary_color, secondary_color, accent, user_id[-1]))
                db.commit()
                return jsonify(status="200", message="Theme successfully changed.", colors=[primary_color, secondary_color, accent])

    return jsonify(status="500", message="Something went wrong.")


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
                db.execute('INSERT INTO admin (email, password, primary_color, secondary_color, accent) VALUES (?, ?, ?, ?, ?)',
                           (email, generate_password_hash(password), '#FFFFFF', '#13131D', '#1E1E2D'))
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
                db.execute('INSERT INTO vendor (email, password, primary_color, secondary_color, accent) VALUES (?, ?, ?, ?, ?)',
                           (email, generate_password_hash(password), '#03A9F4', '#0277BD', '#014972'))
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
                db.execute('INSERT INTO customer (email, password, primary_color, secondary_color, accent) VALUES (?, ?, ?, ?, ?)',
                           (email, generate_password_hash(password), '#FF5722', '#D84315', '#922E10'))
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
                authenticated.append('admin' + str(admin['id']))
                return jsonify(status="200", message="Admin {} logged in.".format(admin['email']), token='admin'+str(admin['id']), colors=[admin['primary_color'], admin['secondary_color'], admin['accent']])
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
                authenticated.append('vendor' + str(vendor['id']))
                return jsonify(status="200", message="Vendor {} logged in.".format(vendor['email']), token='vendor'+str(vendor['id']), colors=[vendor['primary_color'], vendor['secondary_color'], vendor['accent']])
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
                authenticated.append('customer' + str(customer['id']))
                return jsonify(status="200", message="Vendor {} logged in.".format(customer['email']), token='customer'+str(customer['id']), colors=[customer['primary_color'], customer['secondary_color'], customer['accent']])

    return jsonify(status="500", message="Something went wrong.")
