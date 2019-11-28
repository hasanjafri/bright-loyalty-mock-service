import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from werkzeug.security import check_password_hash, generate_password_hash

from src.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.before_app_request
def load_logged_in_admin():
    admin_id = session.get('admin_id')

    if admin_id is None:
        g.admin = None
    else:
        g.admin = get_db().execute('SELECT * FROM admin WHERE id = ?', (admin_id,)).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.admin is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


@bp.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']
        db = get_db()

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

    return jsonify(status="500", message="Something went wrong.")


@bp.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']
        db = get_db()
        admin = db.execute(
            'SELECT * FROM admin WHERE email = ?', (email,)).fetchone()

        if admin is None:
            return jsonify(status="400", message="Incorrect Email or Password")
        elif not check_password_hash(admin['password'], password):
            return jsonify(status="400", message="Incorrect Email or Password")
        else:
            session.clear()
            session['admin_id'] = admin['id']
            return jsonify(status="200", message="Admin {} logged in.".format(admin['email']), token=admin['id'])

    return jsonify(status="500", message="Something went wrong.")
