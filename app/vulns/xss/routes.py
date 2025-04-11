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
        log.write("================================\n")

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
            feedback = "✅ Well done! Your code escapes the input."
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
            log.write("================================\n")

    return render_template('vulns/xss.html', comment=comment)

@bp_xss.route('/summary')
@login_required
def xss_summary():
    return render_template('vulns/xss_summary.html')