from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from datetime import datetime
import html

bp_xss = Blueprint('xss', __name__, url_prefix='/xss')

def log_fix_attempt(username, submitted_code, is_safe):
    with open('logs/general_logs.txt', 'a') as log:
        log.write("\n===== XSS FIX ATTEMPT =====\n")
        log.write(f"User: {username}\n")
        log.write(f"Time: {datetime.now()}\n")
        log.write(f"Safe: {is_safe}\n")
        log.write(f"Code:\n{submitted_code}\n")
        log.write("================================")

@bp_xss.route('/fix', methods=['GET', 'POST'])
@login_required
def xss_fix():
    feedback = None
    is_safe = False
    submitted_code = ""
    safe_output = ""

    if request.method == 'POST':
        submitted_code = request.form.get('code', '')

        if "html.escape" in submitted_code:
            is_safe = True
            test_input = '<script>alert(1)</script>'
            safe_output = html.escape(test_input)
            feedback = "✅ Well done! Your code escapes the input (or you used html.escape in some way)."
        else:
            feedback = "❌ Your function does not escape HTML. Try using `html.escape()`."

        log_fix_attempt(current_user.username, submitted_code, is_safe)

    return render_template('vulns/xss_fix.html', feedback=feedback, code=submitted_code, output=safe_output)

@bp_xss.route('/', methods=['GET', 'POST'])
@login_required
def xss_demo():
    comment = None
    if request.method == 'POST':
        comment = request.form.get('comment')

        # Log entry
        with open('logs/general_logs.txt', 'a') as log:
            log.write("\n===== XSS ATTEMPT =====\n")
            log.write(f"User: {current_user.username}\n")
            log.write(f"Time: {datetime.now()}\n")
            log.write(f"Comment: {comment}\n")
            log.write("================================")

    return render_template('vulns/xss.html', comment=comment)

@bp_xss.route('/summary')
@login_required
def xss_summary():
    return render_template('vulns/xss_summary.html')

@bp_xss.route('/quiz', methods=['GET', 'POST'])
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
            'q1': 'c',  # Stored XSS
            'q2': 'stored',  # alert("XSS")
            'q3': 'z',  # Executes it
            'q4': 'b',  # alert("xss")
            'q5_1': 'B',  # XSS via query string → Reflected
            'q5_2': 'C',  # XSS in database → Stored
            'q5_3': 'A'   # XSS via JS on client → DOM
        }

        explanations = {
            'q1': "Stored XSS occurs when a malicious script is stored on the server and is later served to users. When victims load the page, the script executes in their browser.",
            'q2': "Stored Cross-Site Scripting (XSS) is generally considered the most dangerous type of XSS attack because it's persistent and affects all users who visit a compromised page. Unlike Reflected XSS, which relies on a user clicking a malicious link, Stored XSS automatically executes the malicious code when a user views the infected content.",
            'q3': "When the browser encounters a `<script>` tag with JavaScript, like `<script>alert('x')</script>`, it executes the script by default. Unless protections like Content Security Policy (CSP) or input sanitization are in place, the script runs in the context of the website.",
            'q4': "`alert(\"xss\")` is a simple but common test payload used in XSS attacks. If it pops up an alert box when inserted into a web page, it confirms that script execution is possible and reveals a vulnerability.",
            'q5_1': "Reflected XSS typically uses query string parameters. If this input is reflected back into the page without filtering, it allows script execution in the user’s browser.",
            'q5_2': "Stored XSS involves injecting a script into a persistent data store, like a database. When another user loads the affected content (e.g., a blog post or comment), the script is delivered and executed in their browser automatically.",
            'q5_3': "DOM-based XSS is a type of XSS where the vulnerability exists in client-side JavaScript, not in the server. It occurs when JavaScript dynamically updates the page based on unsanitized user input. Thus, it allows an attacker to inject scripts by manipulating the DOM."
        }

        score = 0
        wrong = {}

        for key, expected in correct.items():
            user_answer = (answers.get(key) or '').strip()

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
            log.write("\n===== QUIZ SUBMISSION: XSS =====\n")
            log.write(f"User: {current_user.username}\n")
            log.write(f"Time: {datetime.now()}\n")
            log.write(f"Score: {score}/{total}\n")
            for q, a in answers.items():
                log.write(f"{q}: {a}\n")
            log.write("================================")

        return render_template(
            'quiz/xss_quiz.html',
            submitted=True,
            score=score,
            total=total,
            passed=passed,
            wrong=wrong
        )
    return render_template('quiz/xss_quiz.html')

