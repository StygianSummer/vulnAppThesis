from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# Define at the module level
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.vulns.sqli.routes import bp_sqli
    app.register_blueprint(bp_sqli)

    from app.vulns.xss.routes import bp_xss
    app.register_blueprint(bp_xss)

    from app.vulns.crypto_fail.routes import bp_crypto
    app.register_blueprint(bp_crypto)

    import base64

    def b64decode_filter(encoded_str):
        try:
            return base64.b64decode(encoded_str).decode('utf-8')
        except Exception:
            return '[Invalid Base64]'
    app.jinja_env.filters['b64decode'] = b64decode_filter
    return app
