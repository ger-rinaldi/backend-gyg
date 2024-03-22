from flask import Blueprint

from presupuestador_gyg_api.api.user_auth import user_auth_bp
from presupuestador_gyg_api.api.admin_user_crud import admin_user_crud_bp

complete_api_bp = Blueprint("api", __name__, url_prefix="/")


complete_api_bp.register_blueprint(user_auth_bp)
complete_api_bp.register_blueprint(admin_user_crud_bp)
