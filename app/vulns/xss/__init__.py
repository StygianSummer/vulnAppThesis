from flask import Blueprint

bp = Blueprint('xss', __name__)

from app.vulns.xss import routes
