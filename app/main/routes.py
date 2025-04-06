from flask import render_template
from flask_login import login_required, current_user  # Make sure current_user is imported
from app.main import bp

@bp.route('/')
@bp.route('/index')
@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@bp.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@bp.route('/user')
@login_required
def user():
    return render_template('user.html')
