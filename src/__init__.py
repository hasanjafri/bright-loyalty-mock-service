import os

from flask import Flask
from flask_cors import CORS


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    cors = CORS(app, resources={r"/auth/*": {"origins": "*"}})
    app.config.from_mapping(SECRET_KEY='dev', DATABASE=os.path.join(
        app.instance_path, 'bright-loyalty.sqlite'))

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.config['CORS_HEADERS'] = 'Content-Type'

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    @app.route('/hello')
    def hello():
        return 'Bright Loyalty Mock Service'

    return app
