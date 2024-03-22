from flask import Blueprint

from presupuestador_gyg_api.api.user_auth import user_auth_bp

complete_api_bp = Blueprint("api", __name__, url_prefix="/")


complete_api_bp.register_blueprint(user_auth_bp)
