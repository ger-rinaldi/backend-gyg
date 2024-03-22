from typing import Dict, Tuple
import bcrypt
from flask import Blueprint, jsonify, make_response, request, Response
from sqlalchemy import or_, select, Select
from sqlalchemy.engine.row import Row

from presupuestador_gyg_api.auth import (
    create_revoked_cookie,
    create_signed_cookie,
    validate_request,
)
from presupuestador_gyg_api.database.session import create_local_session
from presupuestador_gyg_api.models import User

user_auth_bp = Blueprint("user", __name__, url_prefix="/user/auth")

# TODO: WRITE CODE DOCUMENTATION


@user_auth_bp.post("/login")
def user_login():
    login_identification: str = request.form.get("identification")
    login_password: str = request.form.get("password")

    wrong_credentials_response: Dict = {
        "message": "User identity (username or email) do not match user password.",
    }

    with create_local_session() as sesh:
        query_statement: Select[Tuple[User]] = select(User).filter(
            or_(
                User.username == login_identification,
                User.email == login_identification,
            )
        )

        queried_user: Row[User] | None = sesh.execute(query_statement).one_or_none()

    if queried_user is None:
        return wrong_credentials_response, 401

    queried_user: User = queried_user[0]

    if not bcrypt.checkpw(
        login_password.encode("UTF-8"), queried_user.password_hash.encode("UTF-8")
    ):
        return wrong_credentials_response, 401

    success_response: Response = make_response(
        jsonify(
            {
                "message": "Successful login",
            },
        )
    )

    success_response.set_cookie(
        **create_signed_cookie(queried_user.username, queried_user.is_admin)
    )

    return success_response, 200


@user_auth_bp.post("/logout")
@validate_request
def user_logout():

    logout_response: Response = make_response(
        jsonify({"message": "Succesful session logout"})
    )

    logout_response.set_cookie(**create_revoked_cookie())

    return logout_response, 200
