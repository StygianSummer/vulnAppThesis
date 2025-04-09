from flask import render_template #it is used, ignore the warning
from flask_login import login_required
from app.main import bp

# Dashboard and static pages
@bp.route('/')
@bp.route('/index')
@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@bp.route('/user')
@login_required
def user():
    return render_template('user.html')

# Other vulnerability pages
@bp.route('/xss')
@login_required
def xss():
    return render_template('vulns/xss.html')

@bp.route('/crypto_fail')
@login_required
def crypto_fail():
    return render_template('vulns/crypto_fail.html')

# Learning pages
@bp.route('/learn')
@login_required
def learn():
    return render_template('learn/overview.html')

@bp.route('/learn/sqli')
@login_required
def learn_sqli():
    return render_template('learn/sqli_learn.html')

@bp.route('/learn/xss')
@login_required
def learn_xss():
    return render_template('learn/xss_learn.html')

@bp.route('/learn/crypto_fail')
@login_required
def learn_crypto():
    return render_template('learn/crypto_fail_learn.html')

# Quiz pages
@bp.route('/final_quiz')
@login_required
def final_quiz():
    return render_template('quiz/final_quiz.html')

@bp.route('/quiz/sqli')
@login_required
def quiz_sqli():
    return render_template('quiz/sqli_quiz.html')

@bp.route('/quiz/xss')
@login_required
def quiz_xss():
    return render_template('quiz/xss_quiz.html')

@bp.route('/quiz/crypto')
@login_required
def quiz_crypto_fail():
    return render_template('quiz/crypto_fail_quiz.html')

import os
from flask import render_template
from flask_login import login_required
from app.main import bp

@bp.route('/logs')
@login_required
def logs():
    log_file = 'logs/general_logs.txt'
    logs_data = {
        'sqli': [],
        'xss': [],
        'quiz': []
    }

    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            content = f.read()

            # Split by delimiter between blocks
            entries = content.split("================================")

            for entry in entries:
                entry = entry.strip()
                if "SQLI ATTEMPT" in entry:
                    logs_data['sqli'].append(entry)
                elif "XSS ATTEMPT" in entry:
                    logs_data['xss'].append(entry)
                elif "QUIZ SUBMISSION" in entry:
                    logs_data['quiz'].append(entry)

    logs_data['sqli'].reverse()
    logs_data['xss'].reverse()
    logs_data['quiz'].reverse()

    return render_template('logs.html', logs=logs_data)
