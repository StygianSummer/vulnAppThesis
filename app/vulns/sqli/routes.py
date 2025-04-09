import sqlite3
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

@bp_sqli.route('/', methods=['GET', 'POST'])
@login_required
def sqli():
    result = []
    executed_query = None

    if request.method == 'POST':
        search_term = request.form['search']
        conn = sqlite3.connect('sqli_demo.db')
        cursor = conn.cursor()

        # ❗️INTENTIONALLY VULNERABLE
        executed_query = f"SELECT * FROM employees WHERE name = '{search_term}'"
        try:
            cursor.execute(executed_query)
            result = cursor.fetchall()
        except Exception as e:
            result = [str(e)]

        conn.close()
        log_query(current_user.username, executed_query, result, "SQLI")

    return render_template('vulns/sqli.html', result=result, query=executed_query)

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

@bp_sqli.route('/summary')
@login_required
def sqli_summary():
    return render_template('vulns/sqli_summary.html')
