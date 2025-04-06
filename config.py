import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'

    # Main user database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'instance', 'app.db')

    # Additional database binds
    SQLALCHEMY_BINDS = {
        'vuln_demo': os.environ.get('VULN_DB_URL') or \
                     'sqlite:///' + os.path.join(basedir, 'instance', 'vuln_demo.db'),
        'logs': os.environ.get('LOGS_DB_URL') or \
                'sqlite:///' + os.path.join(basedir, 'instance', 'logs.db')
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False