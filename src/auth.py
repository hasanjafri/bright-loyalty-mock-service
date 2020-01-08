import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash

from src.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

authenticated = []


@bp.route('/loadTableData', methods=['GET'])
def load_table_data():
    barGraphOneData = [
        {
            'month': 'January',
            'signups': 1000
        },
        {
            'month': 'February',
            'signups': 2000
        },
        {
            'month': 'March',
            'signups': 3100
        },
        {
            'month': 'May',
            'signups': 1400
        },
        {
            'month': 'June',
            'signups': 507
        },
        {
            'month': 'July',
            'signups': 684
        },
        {
            'month': 'August',
            'signups': 1257
        },
        {
            'month': 'September',
            'signups': 2035
        },
        {
            'month': 'October',
            'signups': 3333
        },
        {
            'month': 'November',
            'signups': 4123
        },
        {
            'month': 'December',
            'signups': 752
        }
    ]

    barGraphTwoData = [
        {
            'vendorType': 'Applications',
            'signups': 1000
        },
        {
            'vendorType': 'Hardware',
            'signups': 2000
        },
        {
            'vendorType': 'Services',
            'signups': 300
        },
        {
            'vendorType': 'Software',
            'signups': 4000
        }
    ]

    barGraphThreeData = [
        {
            'month': 'January',
            'signups': 10000
        },
        {
            'month': 'February',
            'signups': 20031
        },
        {
            'month': 'March',
            'signups': 30031
        },
        {
            'month': 'May',
            'signups': 4300
        },
        {
            'month': 'June',
            'signups': 5004
        },
        {
            'month': 'July',
            'signups': 6005
        },
        {
            'month': 'August',
            'signups': 7006
        },
        {
            'month': 'September',
            'signups': 5234
        },
        {
            'month': 'October',
            'signups': 1235
        },
        {
            'month': 'November',
            'signups': 2346
        },
        {
            'month': 'December',
            'signups': 3543
        }
    ]

    return jsonify(status="200", data=[barGraphOneData, barGraphTwoData, barGraphThreeData])


@bp.route('/check', methods=['POST'])
def check_authenticated():
    if request.method == 'POST':
        data = request.get_json()
        token = data['token']
        session_id = data['session_id']
        userType = token[0:-1]
        db = get_db()

        print(token, session_id)

        if session_id in authenticated:
            if userType == 'admin':
                admin = db.execute(
                    'SELECT * FROM admin WHERE id = ?', (token[-1],)).fetchone()

                if admin is None:
                    return jsonify(status="400", message="Unauthenticated")
                else:
                    theme = db.execute(
                        'SELECT * FROM theme WHERE admin_id = ?', (token[-1],)).fetchone()
                    return jsonify(status="200", colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], token=token, email=admin['email'], first_name=admin['first_name'], last_name=admin['last_name'])
            elif userType == 'vendor':
                vendor = db.execute(
                    'SELECT * FROM vendor WHERE id = ?', (token[-1],)).fetchone()

                if vendor is None:
                    return jsonify(status="400", message="Unauthenticated")
                else:
                    theme = db.execute(
                        'SELECT * FROM theme WHERE vendor_id = ?', (token[-1],)).fetchone()
                    return jsonify(status="200", colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], token=token, email=vendor['email'], first_name=vendor['first_name'], last_name=vendor['last_name'])
            elif userType == 'party':
                party = db.execute(
                    'SELECT * FROM party WHERE id = ?', (token[-1],)).fetchone()

                if party is None:
                    return jsonify(status="400", message="Unauthenticated")
                else:
                    theme = db.execute(
                        'SELECT * FROM theme WHERE party_id = ?', (token[-1],)).fetchone()
                    return jsonify(status="200", colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], token=token, email=party['email'], first_name=party['first_name'], last_name=party['last_name'])
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
            theme = db.execute(
                'SELECT * FROM theme WHERE admin_id = ?', (user_id[-1],)).fetchone()

            if theme is None:
                return jsonify(status="400", message="An error occurred while changing theme for user")
            else:
                db.execute('UPDATE theme set primary_color = ?, secondary_color = ?, accent = ? where admin_id = ?',
                           (primary_color, secondary_color, accent, user_id[-1]))
                db.commit()
                return jsonify(status="200", message="Theme successfully changed.", colors=[primary_color, secondary_color, accent])
        elif userType == 'vendor':
            theme = db.execute(
                'SELECT * FROM theme WHERE vendor_id = ?', (user_id[-1],)).fetchone()

            if theme is None:
                return jsonify(status="400", message="An error occurred while changing theme for user")
            else:
                db.execute('UPDATE theme set primary_color = ?, secondary_color = ?, accent = ? where vendor_id = ?',
                           (primary_color, secondary_color, accent, user_id[-1]))
                db.commit()
                return jsonify(status="200", message="Theme successfully changed.", colors=[primary_color, secondary_color, accent])
        elif userType == 'party':
            theme = db.execute(
                'SELECT * FROM theme WHERE party_id = ?', (user_id[-1],)).fetchone()

            if theme is None:
                return jsonify(status="400", message="An error occurred while changing theme for user")
            else:
                db.execute('UPDATE theme set primary_color = ?, secondary_color = ?, accent = ? where party_id = ?',
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
        first_name = data['first_name']
        last_name = data['last_name']
        db = get_db()

        if userType == 'admin':
            if not email:
                return jsonify(status="400", message="Email is required")
            elif not password:
                return jsonify(status="400", message="Password is required")
            elif db.execute('SELECT id FROM admin WHERE email = ?', (email,)).fetchone() is not None:
                return jsonify(status="409", message="{} is already registered".format(email))
            else:
                db.execute('INSERT INTO admin (email, password, first_name, last_name) VALUES (?, ?, ?, ?)',
                           (email, generate_password_hash(password), first_name, last_name))
                admin = db.execute(
                    'SELECT * FROM admin WHERE email = ?', (email,)).fetchone()
                if admin:
                    db.execute('INSERT INTO theme (primary_color, secondary_color, accent, admin_id) VALUES (?, ?, ?, ?)',
                               ('#FFFFFF', '#13131D', '#1E1E2D', admin['id']))
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
                db.execute('INSERT INTO vendor (email, password, first_name, last_name) VALUES (?, ?, ?, ?)',
                           (email, generate_password_hash(password), first_name, last_name))
                vendor = db.execute(
                    'SELECT * FROM vendor WHERE email = ?', (email,)).fetchone()
                if vendor:
                    db.execute('INSERT INTO theme (primary_color, secondary_color, accent, vendor_id) VALUES (?, ?, ?, ?)',
                               ('#03A9F4', '#0277BD', '#014972', vendor['id']))
                db.commit()
                return jsonify(status="200", message="Vendor {} successfully created".format(email))
        elif userType == 'party':
            vendor_id = db.execute(
                'SELECT * FROM vendor WHERE email = ?', (email,)).fetchone()
            if not vendor_id:
                vendor_id = ''

            if not email:
                return jsonify(status="400", message="Email is required")
            elif not password:
                return jsonify(status="400", message="Password is required")
            elif not vendor_id:
                return jsonify(status="400", message="Vendor ID is required")
            elif db.execute('SELECT id FROM party WHERE email = ?', (email,)).fetchone() is not None:
                return jsonify(status="409", message="{} is already registered".format(email))
            else:
                db.execute('INSERT INTO party (email, password, first_name, last_name, vendor_id) VALUES (?, ?, ?, ?, ?)',
                           (email, generate_password_hash(password), first_name, last_name, vendor_id))
                party = db.execute(
                    'SELECT * FROM party WHERE email = ?', (email,)).fetchone()
                if party:
                    db.execute('INSERT INTO theme (primary_color, secondary_color, accent, party_id) VALUES (?, ?, ?, ?)',
                               ('#FF5722', '#D84315', '#922E10', party['id']))
                db.commit()
                return jsonify(status="200", message="party {} successfully created".format(email))

    return jsonify(status="500", message="Something went wrong.")


@bp.route('/loginAlt', methods=['POST'])
def loginAlt():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        session_id = data['session_id']
        token = data['token']
        alt_token = data['alt_token']
        userType = data['userType']
        db = get_db()

        print(userType)

        if session_id in authenticated:
            if userType == 'admin':
                return jsonify(status="400", message="Invalid Request for UserType Admin")
            elif userType == 'party':
                party = db.execute(
                    'SELECT * FROM party WHERE id = ?', (alt_token[-1],)).fetchone()

                if party:
                    theme = db.execute(
                        'SELECT * FROM theme WHERE party_id = ?', (alt_token[-1],)).fetchone()
                    print(theme['primary_color'],
                          theme['secondary_color'], theme['accent'])
                    return jsonify(status="200", colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], first_name=party['first_name'], last_name=party['last_name'])
            elif userType == 'vendor':
                vendor = db.execute(
                    'SELECT * FROM vendor WHERE id = ?', (alt_token[-1],)).fetchone()

                if vendor:
                    theme = db.execute(
                        'SELECT * FROM theme WHERE vendor_id = ?', (alt_token[-1],)).fetchone()
                    print(theme['primary_color'],
                          theme['secondary_color'], theme['accent'])
                    return jsonify(status="200", colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], first_name=vendor['first_name'], last_name=vendor['last_name'])
            else:
                return jsonify(status="500", message="Something went wrong.")


@bp.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']
        userType = data['userType']
        db = get_db()

        print(email, password, userType)

        if userType == 'admin':
            admin = db.execute(
                'SELECT * FROM admin WHERE email = ?', (email,)).fetchone()

            if admin is None:
                return jsonify(status="400", message="Incorrect Email or Password")
            elif not check_password_hash(admin['password'], password):
                return jsonify(status="400", message="Incorrect Email or Password")
            else:
                theme = db.execute(
                    'SELECT * FROM theme WHERE admin_id = ?', (admin['id'],)).fetchone()

                session.clear()
                session_id = str(uuid4())
                session['admin_id'] = session_id
                authenticated.append(session_id)
                return jsonify(status="200", message="Admin {} logged in.".format(admin['email']), token='admin'+str(admin['id']), colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], email=admin['email'], first_name=admin['first_name'], last_name=admin['last_name'], session_id=session_id)
        elif userType == 'vendor':
            vendor = db.execute(
                'SELECT * FROM vendor WHERE email = ?', (email,)).fetchone()

            if vendor is None:
                return jsonify(status="400", message="Incorrect Email or Password")
            elif not check_password_hash(vendor['password'], password):
                return jsonify(status="400", message="Incorrect Email or Password")
            else:
                party_token = ''

                party = db.execute(
                    'SELECT * FROM party WHERE vendor_id = ?', (vendor['id'],)).fetchone()

                if party is not None:
                    party_token = 'party' + str(party['id'])

                theme = db.execute(
                    'SELECT * FROM theme WHERE vendor_id = ?', (vendor['id'],)).fetchone()

                session.clear()
                session_id = str(uuid4())
                session['vendor_id'] = session_id
                authenticated.append(session_id)
                return jsonify(status="200", message="Vendor {} logged in.".format(vendor['email']), token='vendor'+str(vendor['id']), colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], alt_token=party_token, email=vendor['email'], first_name=vendor['first_name'], last_name=vendor['last_name'], session_id=session_id)
        elif userType == 'party':
            party = db.execute(
                'SELECT * FROM party WHERE email = ?', (email,)).fetchone()

            if party is None:
                return jsonify(status="400", message="Incorrect Email or Password")
            elif not check_password_hash(party['password'], password):
                return jsonify(status="400", message="Incorrect Email or Password")
            else:
                vendor_token = ''

                vendor = db.execute(
                    'SELECT * FROM vendor WHERE id = ?', (party['vendor_id'],)).fetchone()

                if vendor is not None:
                    vendor_token = 'vendor' + str(vendor['id'])

                theme = db.execute(
                    'SELECT * FROM theme WHERE party_id = ?', (party['id'],)).fetchone()

                session.clear()
                session_id = str(uuid4())
                session['party_id'] = session_id
                authenticated.append(session_id)
                return jsonify(status="200", message="Party {} logged in.".format(party['email']), token='party'+str(party['id']), colors=[theme['primary_color'], theme['secondary_color'], theme['accent']], alt_token=vendor_token, email=party['email'], first_name=party['first_name'], last_name=party['last_name'], session_id=session_id)

    return jsonify(status="500", message="Something went wrong.")
