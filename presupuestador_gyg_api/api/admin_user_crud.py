from typing import Dict
from pydantic import ValidationError
from flask import Blueprint, jsonify, make_response, request, Response

from sqlalchemy import select, Select, or_
from sqlalchemy.exc import IntegrityError
import bcrypt

from presupuestador_gyg_api.auth import validate_request

from presupuestador_gyg_api.database.session import create_local_session
from presupuestador_gyg_api import schemas, models

admin_user_crud_bp = Blueprint(
    "admin_user_crud",
    __name__,
    url_prefix="/admin/user",
)


@admin_user_crud_bp.post("/create")
@validate_request
def create_new_user():

    user_request_info: Dict = request.form.to_dict()

    try:
        validated_user_info = dict(schemas.User(**user_request_info))
    except ValidationError as ve:

        errors_list = []

        for error in ve.errors():

            error_object = {
                "field": error["loc"][0],
                "invalid_input": error["input"],
                "error_info": error["msg"],
            }

            if error_object["field"] == "password":
                error_object["invalid_input"] = len(error["input"])

            errors_list.append(error_object)

        return {"message": "User invalid info", "errors": errors_list}, 400

    plain_pass = validated_user_info.pop("password")

    hashed_password = bcrypt.hashpw(plain_pass.encode("UTF-8"), bcrypt.gensalt())

    validated_user_info["password_hash"] = hashed_password

    try:
        with create_local_session() as db_session:
            user_object = models.User(**validated_user_info)
            db_session.add(user_object)
            db_session.commit()
    except IntegrityError as ie:
        offending_field = ie.orig.args[1].split(".")[-1].strip("'")
        return {"message": f"User with that {offending_field} already exists"}, 400

    return {
        "message": f"User {validated_user_info['username']} created succesfully"
    }, 200


@admin_user_crud_bp.post("/update")
@validate_request
def update_existing_user():
    pass


@admin_user_crud_bp.get("/all")
@validate_request
def read_all_users():

    with create_local_session() as db_session:
        read_all_query = select(models.User)

        all_users_query_result = db_session.execute(read_all_query).all()

    all_users_dicts_list = []

    for user in all_users_query_result:
        user_as_dict = {}
        for column in models.User.__table__.columns:
            if column.name not in [
                "password_hash",
                "personal_session_salt",
                "session_key",
            ]:
                user_as_dict.setdefault(column.name, getattr(user[0], column.name))
        all_users_dicts_list.append(user_as_dict)

    return jsonify(users_list=all_users_dicts_list), 200


@admin_user_crud_bp.get("/<user_id_or_username>")
@validate_request
def read_user_by_id_or_username(user_id_or_username: str):

    with create_local_session() as db_session:
        read_user_query = select(models.User).where(
            or_(
                models.User.username == user_id_or_username,
                models.User.id == user_id_or_username,
            )
        )

        user_result = db_session.execute(read_user_query).one_or_none()

    if user_result is None:
        return {"message": f"No username identificated by {user_id_or_username}"}, 400

    user_as_dict = {}

    for column in models.User.__table__.columns:
        if column.name not in [
            "password_hash",
            "personal_session_salt",
            "session_key",
        ]:
            user_as_dict.setdefault(column.name, getattr(user_result[0], column.name))

    return user_as_dict, 200
