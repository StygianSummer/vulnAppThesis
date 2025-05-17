import random

from flask import request, render_template, url_for  # it is used, ignore the warning
from flask_login import login_required, current_user
from app.main import bp
from datetime import datetime
import os

# Dashboard and static pages
@bp.route('/')
@bp.route('/index')
@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

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
    learn_pages = [
        ('SQL Injection', url_for('main.learn_sqli')),
        ('Cross Site Scripting (XSS)', url_for('main.learn_xss')),
        ('Cryptographic Failures', url_for('main.learn_crypto'))
    ]
    recommended_topic = random.choice(learn_pages)
    return render_template('learn/overview.html', recommended_topic=recommended_topic)

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

# Quiz pages later to be moved except for final quiz which stays here
from flask import request, render_template
from flask_login import login_required, current_user
from datetime import datetime

@bp.route('/final_quiz', methods=['GET', 'POST'])
@login_required
def final_quiz():
    if request.method == 'POST':
        answers = {
            'q1': request.form.get('q1'),
            'q2': request.form.get('q2'),
            'q3': request.form.get('q3'),
            'q4': request.form.get('q4'),
            'q5_1': request.form.get('q5_1'),
            'q5_2': request.form.get('q5_2'),
            'q5_3': request.form.get('q5_3'),
            'q6': request.form.get('q6'),
            'q7': request.form.get('q7'),
            'q8_1': request.form.get('q8_1'),
            'q8_2': request.form.get('q8_2'),
            'q8_3': request.form.get('q8_3'),
            'q9': request.form.get('q9'),
            'q10': request.form.get('q10'),
            'q11': request.form.get('q11'),
            'q12': request.form.get('q12'),
            'q13': request.form.get('q13'),
            'q14': request.form.get('q14'),
            'q15': request.form.get('q15')
        }

        correct = {
            'q1': 'XSS',
            'q2': 'b',
            'q3': 'd',
            'q4': 'b',
            'q5_1': 'B',
            'q5_2': 'C',
            'q5_3': 'A',
            'q6': 'b',
            'q7': 'c',
            'q8_1': 'B',
            'q8_2': 'C',
            'q8_3': 'A',
            'q9': 'a',
            'q10': 'c',
            'q11': 'b',
            'q12': 'DOM',
            'q13': 'b',
            'q14': 'b',
            'q15': 'b'
        }

        explanations = {
            'q1': "To prevent XSS, output encoding ensures that user inputs can't be interpreted as executable scripts.",
            'q2': "A vulnerability is a flaw or weakness that can be exploited for malicious purposes.",
            'q3': "Slow loading is a performance issue, not a security vulnerability.",
            'q4': "Not all bugs create security issues. A vulnerability is a bug that leads to a security risk.",
            'q5_1': "SQL Injection alters backend SQL logic.",
            'q5_2': "XSS injects scripts into web pages.",
            'q5_3': "Cryptographic failures expose sensitive data due to weak or absent encryption.",
            'q6': "Injecting a script to steal session cookies is a real-world vulnerability.",
            'q7': "SQL Injection abuses trust in user input by executing harmful queries.",
            'q8_1': "Unsanitized user input is a major cause of XSS vulnerabilities.",
            'q8_2': "Without salting, hashes for identical passwords are the same, aiding attackers.",
            'q8_3': "SQL Injection alters the structure of the original SQL query.",
            'q9': "A successful SQL Injection can let an attacker modify or delete data.",
            'q10': "Prepared statements treat input as data, not executable code, preventing SQLi.",
            'q11': "HTML escaping or encoding user input prevents scripts from executing in the browser.",
            'q12': "DOM-based XSS happens when JavaScript writes untrusted data into the page.",
            'q13': "A password-safe hash must be one-way, so original data can’t be retrieved.",
            'q14': "If passwords are stored in plaintext, anyone with access can read them.",
            'q15': "Encrypting large files is not an issue; storing plaintext passwords or using HTTP are."
        }

        wrong = {}
        score = 0

        for key, expected in correct.items():
            user_answer = (answers.get(key) or '').strip()

            if key == 'q12':
                if user_answer.lower() in ['dom', 'dom based', 'dom-based']:
                    score += 1
                else:
                    wrong[key] = {
                        'your_answer': user_answer or 'Blank',
                        'correct_answer': 'DOM or DOM-based',
                        'explanation': explanations[key]
                    }
            else:
                if user_answer.lower() == expected.lower():
                    score += 1
                else:
                    wrong[key] = {
                        'your_answer': user_answer or 'Blank',
                        'correct_answer': expected,
                        'explanation': explanations[key]
                    }

        total = len(correct)
        passed = score >= 12

        with open('logs/general_logs.txt', 'a') as log:
            log.write("\n===== QUIZ SUBMISSION: FINAL QUIZ =====\n")
            log.write(f"User: {current_user.username}\n")
            log.write(f"Time: {datetime.now()}\n")
            log.write(f"Score: {score}/{total}\n")
            for q, a in answers.items():
                log.write(f"{q}: {a}\n")
            log.write("================================")

        return render_template(
            'quiz/final_quiz.html',
            submitted=True,
            score=score,
            total=total,
            passed=passed,
            wrong=wrong
        )

    return render_template('quiz/final_quiz.html')



@bp.route('/logs')
@login_required
def logs():
    log_file = 'logs/general_logs.txt'
    logs_data = {
        'sqli': [],
        'xss': [],
        'quiz': [],
        'crypto': []  # New section for CRYPTO logs
    }

    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            content = f.read()

            entries = content.split("================================")

            for entry in entries:
                entry = entry.strip()
                if "SQLI ATTEMPT" in entry:
                    logs_data['sqli'].append(entry)
                elif "XSS ATTEMPT" in entry or "XSS FIX ATTEMPT" in entry:
                    logs_data['xss'].append(entry)
                elif "CRYPTO ATTEMPT" in entry:
                    logs_data['crypto'].append(entry)  # Add CRYPTO logs
                elif "QUIZ SUBMISSION: SQLI" in entry:
                    logs_data['quiz'].append(" [SQLI QUIZ]\n" + entry)
                elif "QUIZ SUBMISSION: XSS" in entry:
                    logs_data['quiz'].append(" [XSS QUIZ]\n" + entry)
                elif "QUIZ SUBMISSION: CRYPTO" in entry:
                    logs_data['quiz'].append(" [CRYPTO QUIZ]\n" + entry)
                elif "QUIZ SUBMISSION: FINAL" in entry:
                    logs_data['quiz'].append(" [Final Quiz]\n" + entry)

    logs_data['sqli'].reverse()
    logs_data['xss'].reverse()
    logs_data['quiz'].reverse()
    logs_data['crypto'].reverse()  # Reverse CRYPTO logs too

    return render_template('logs.html', logs=logs_data)
