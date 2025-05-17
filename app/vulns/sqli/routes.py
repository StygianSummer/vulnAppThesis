import sqlite3
import html
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_required, current_user
bp_sqli = Blueprint('sqli', __name__, url_prefix='/sqli')

def log_query(username, query, result, vuln_type="SQLI"):
    with open('logs/general_logs.txt', 'a') as log_file:
        log_file.write(f"\n===== {vuln_type} ATTEMPT =====\n")
        log_file.write(f"User: {username}\n")
        log_file.write(f"Time: {datetime.now()}\n")
        log_file.write(f"Query: {query}\n")
        log_file.write(f"Result: {result}\n")
        log_file.write("================================")

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
            result = cursor.fetchall()  # Fetching all results
        except Exception as e:
            try:
                cursor.executescript(executed_query)
                result = "This query does not print anything"
            except Exception as e:
                result  = "exception: "+str(e)

        # Commit changes (for non-SELECT queries like INSERT, UPDATE, DELETE, etc.)
        conn.commit()
        conn.close()

        # Log the query and result
        log_query(current_user.username, executed_query, result, "SQLI")
    return render_template('vulns/sqli.html', result=result, query=executed_query)

# 🔁 Reset DB Route
@bp_sqli.route('/reset', methods=['POST'])
@login_required
def sqli_reset():
    conn = sqlite3.connect('sqli_demo.db')
    cursor = conn.cursor()

    cursor.executescript("""
        DROP TABLE IF EXISTS employees;
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            role TEXT,
            salary INTEGER
        );
        INSERT INTO employees (name, role, salary) VALUES 
            ('Alice', 'Manager', 80000),
            ('Bob', 'Developer', 65000),
            ('Charlie', 'Analyst', 60000),
            ('Rom', 'CEO', 1000000),
            ('Betty', 'Intern', 60000);
    """)

    conn.commit()
    conn.close()

    log_query(current_user.username, "RESET DATABASE", "Reset successful", "SQLI")
    return redirect(url_for('sqli.sqli'))

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
            'q1': 'c',  # "They separate data from SQL logic"
            'q2': 'c',  # "It lets attackers inject malicious SQL"
            'q3': 'b',  # "Always evaluates to TRUE"
            'q4': 'parameterized',  # Accepts prepared as well (see below)
            'q5_1': 'C',  # Dangerous practice
            'q5_2': 'B',  # Safe query method
            'q5_3': 'A'   # SQLi payload
        }

        acceptable_q4 = ['parameterized', 'prepared']

        explanations = {
            'q1': "Parameterized queries prevent SQL injection ensuring that user inputs are treated as data and not executable SQL. This separates logic from input and avoids malicious SQL to be executed.",
            'q2': "Directly combining user input with SQL queries lets attackers create inputs that change intended SQL logic. This in turn potentially exposes or allows attackers to manipulate data and is the main reason for SQL Injection.",
            'q3': "The payload `'1' OR '1'='1'` always evaluates to TRUE in SQL. It returns all rows from a table and is commonly used in SQL Injection attacks to defeat authentication.",
            'q4': "The best way to prevent SQL Injection is by using parameterized or prepared statements. These statements bind inputs as data and prevent them from being executed as part of the SQL command.",
            'q5_1': "Accepting input without sanitization or validation allows attackers to inject harmful SQL. It's one of the most common causes of SQL injection.",
            'q5_2': "Prepared statements use placeholders for user input and compile the SQL code separately, ensuring inputs can't alter the SQL structure. This reduces the risk of SQL injection.",
            'q5_3': "'; DROP TABLE users; --' is an SQL Injection payload to terminate a query and delete a table."
        }

        wrong = {}
        score = 0

        for key, expected in correct.items():
            user_answer = (answers.get(key) or '').strip()

            # Special handling for Q4 (accept both terms)
            if key == 'q4':
                if user_answer.lower() in acceptable_q4:
                    score += 1
                else:
                    wrong[key] = {
                        'your_answer': user_answer or 'Blank',
                        'correct_answer': 'parameterized / prepared'
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
        passed = score >= 6

        # Log submission
        with open('logs/general_logs.txt', 'a') as log:
            log.write("\n===== QUIZ SUBMISSION: SQLI =====\n")
            log.write(f"User: {current_user.username}\n")
            log.write(f"Time: {datetime.now()}\n")
            log.write(f"Score: {score}/{total}\n")
            for q, a in answers.items():
                log.write(f"{q}: {a}\n")
            log.write("================================")

        return render_template(
            'quiz/sqli_quiz.html',
            submitted=True,
            score=score,
            total=total,
            passed=passed,
            wrong=wrong
        )
    return render_template('quiz/sqli_quiz.html')
