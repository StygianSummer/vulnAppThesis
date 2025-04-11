import sqlite3
import html
from datetime import datetime
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

bp_sqli = Blueprint('sqli', __name__, url_prefix='/sqli')

def log_query(username, query, result, vuln_type="SQLI"):
    with open('logs/general_logs.txt', 'a') as log_file:
        log_file.write(f"\n===== {vuln_type} ATTEMPT =====\n")
        log_file.write(f"User: {username}\n")
        log_file.write(f"Time: {datetime.now()}\n")
        log_file.write(f"Query: {query}\n")
        log_file.write(f"Result: {result}\n")
        log_file.write(f"===============================\n")

# 🔓 Vulnerable Demo
@bp_sqli.route('/', methods=['GET', 'POST'])
@login_required
def sqli():
    result = []
    executed_query = None

    if request.method == 'POST':
        search_term = request.form['search']
        conn = sqlite3.connect('sqli_demo.db')
        cursor = conn.cursor()

        executed_query = f"SELECT * FROM employees WHERE name = '{search_term}'"
        try:
            cursor.execute(executed_query)
            result = cursor.fetchall()
        except Exception as e:
            result = [str(e)]

        conn.close()
        log_query(current_user.username, executed_query, result, "SQLI")

    return render_template('vulns/sqli.html', result=result, query=executed_query)

# 🔐 Fixed Version
@bp_sqli.route('/fixed', methods=['GET', 'POST'])
@login_required
def sqli_fixed():
    result = []
    executed_query = None

    if request.method == 'POST':
        search_term = request.form['search']
        conn = sqlite3.connect('sqli_demo.db')
        cursor = conn.cursor()

        executed_query = "SELECT * FROM employees WHERE name = ?"
        try:
            cursor.execute(executed_query, (search_term,))
            result = cursor.fetchall()
        except Exception as e:
            result = [str(e)]

        conn.close()
        log_query(current_user.username, executed_query, result, "SQLI")

    return render_template('vulns/sqli_fixed.html', result=result, query=executed_query)

# 📘 Summary Page
@bp_sqli.route('/summary')
@login_required
def sqli_summary():
    return render_template('vulns/sqli_summary.html')

# SQLi Quiz
@bp_sqli.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    if request.method == 'POST':
        answers = {
            'q1': request.form.get('q1'),
            'q2': request.form.get('q2'),
            'q3': request.form.get('q3'),
            'q4': request.form.get('q4'),
            'q5_1': request.form.get('q5_1'),
            'q5_2': request.form.get('q5_2'),
            'q5_3': request.form.get('q5_3')
        }

        correct = {
            'q1': 'opt2',
            'q2': 'opt1',
            'q3': 'x',
            'q4': 'x',
            'q5_1': 'A',
            'q5_2': 'B',
            'q5_3': 'C'
        }

        wrong = {}
        score = 0

        for key in correct:
            user_answer = (answers.get(key) or '').strip()
            expected = correct[key].strip()
            if user_answer.lower() == expected.lower():
                score += 1
            else:
                wrong[key] = {
                    'your_answer': user_answer or 'Blank',
                    'correct_answer': expected
                }

        total = len(correct)
        passed = score >= 6

        # Log submission
        with open('logs/general_logs.txt', 'a') as log:
            log.write("\n===== QUIZ SUBMISSION: SQLI =====\n")
            log.write(f"User: {current_user.username}\n")
            log.write(f"Time: {datetime.now()}\n")
            log.write(f"Score: {score}/{total}\n")
            for q, a in answers.items():
                log.write(f"{q}: {a}\n")
            log.write("================================\n")

        return render_template(
            'quiz/sqli_quiz.html',
            submitted=True,
            score=score,
            total=total,
            passed=passed,
            wrong=wrong
        )

    return render_template('quiz/sqli_quiz.html')
