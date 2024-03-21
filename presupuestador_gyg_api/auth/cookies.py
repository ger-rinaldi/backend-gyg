from typing import Optional
import datetime
import functools
from os import getenv
from secrets import token_urlsafe
from typing import Any, Callable, Dict, Tuple, Union

from flask import Response, request
from itsdangerous import BadSignature
from sqlalchemy import Select, select
from sqlalchemy.engine.row import Row

from presupuestador_gyg_api.auth import sign, token
from presupuestador_gyg_api.database.session import create_local_session
from presupuestador_gyg_api.models import User


def create_signed_cookie(username: str, is_admin: bool) -> Dict[str, Any]:
    """
    Create a signed cookie containing session information for the user.

    This function creates a new session token for the given user, and sets the
    appropriate cookie parameters based on the environment variables.

    Args:
    - username (str): The username of the user.
    - is_admin (bool): A boolean indicating if the user is an admin.

    Returns:
    - dict: A dictionary containing the session cookie information.

    """
    max_age: datetime.timedelta = datetime.timedelta(
        hours=float(getenv("COOKIE_MAX_AGE"))
    )
    expires: datetime.datetime = datetime.datetime.now(datetime.timezone.utc) + max_age

    session_cookies: Dict[str, Any] = {
        "key": getenv("COOKIE_KEY"),
        "value": token.create_session_token(username, is_admin),
        "max_age": max_age,
        "expires": expires,
        "path": "/",
        "secure": bool(getenv("COOKIE_SECURE")),
        "httponly": bool(getenv("COOKIE_HTTPONLY")),
        "samesite": getenv("COOKIE_SAMESITE"),
    }

    return session_cookies


def create_revoked_cookie() -> Dict[str, Any]:
    """
    Create a revoked cookie containing a random token to invalidate user sessions.

    This function creates a new revoked cookie by setting the token value to a random
    token and setting the appropriate cookie parameters based on the environment variables.

    Returns:
    - dict: A dictionary containing the revoked cookie information.
    """

    max_age: datetime.timedelta = datetime.timedelta(days=300)
    expires: datetime.datetime = datetime.datetime.now(datetime.timezone.utc) + max_age

    session_cookies: Dict[str, Any] = {
        "key": getenv("COOKIE_KEY"),
        "value": token_urlsafe(76),
        "max_age": max_age,
        "expires": expires,
        "path": "/",
        "secure": bool(getenv("COOKIE_SECURE")),
        "httponly": bool(getenv("COOKIE_HTTPONLY")),
        "samesite": getenv("COOKIE_SAMESITE"),
    }

    return session_cookies


def validate_request(func: Callable) -> Union[Callable, Response]:
    """
    A decorator to validate the request by checking if a valid session exists.

    If no valid session is found, it returns a response with a message and a 200 status code.

    Otherwise, it proceeds to the decorated function.


    Args:
    - func (function): The function to be decorated.

    Returns:
    - function: A wrapper function with the added request validation,
    otherwise it returns a Response with error message.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Union[Callable, Response]:

        if not _is_valid_cookie_session_key():
            return {"message": "User not logged in", "redirect_url": "/login"}, 401

        return func(*args, **kwargs)

    return wrapper


def _is_valid_cookie_session_key() -> bool:
    """
    Check if the given session key is valid and belongs to a valid user.

    The function retrieves the session key from the request's cookies, validates the
    key by checking if it is properly signed and if it exists in the database and
    if it has already expired.

    Returns:
    - bool: True if the cookie is valid, False otherwise.
    """

    cookie_session_id: Union[str, None] = request.cookies.get(
        getenv("COOKIE_KEY"), None
    )

    if cookie_session_id is None:
        return False

    if not _is_signed_cookie(cookie_session_id):
        return False

    unsigned_cookie_key = sign.privilege_based_unsign(cookie_session_id)

    if not _is_registered_cookie(unsigned_cookie_key):
        return False

    queried_user = _get_user_by_session_key(unsigned_cookie_key)

    if not token.is_valid_user_key(unsigned_cookie_key, queried_user):
        return False

    if not _is_fresh_cookie(
        request.cookies.get("Expires"), request.cookies.get("Max-Age")
    ):

        return False

    return True


def _is_signed_cookie(cookie_session_value: str) -> bool:
    """
    Check if the cookie session value is signed.

    Args:
    - cookie_session_value (str): The session value to be checked.

    Returns:
    - bool: True if the session value is signed, False otherwise.
    """

    try:
        unsigned_cookie_key: str = sign.privilege_based_unsign(cookie_session_value)
    except BadSignature:
        return False

    queried_user = _get_user_by_session_key(cookie_session_value)

    return True


def _is_registered_cookie(unsigned_session_key: str) -> bool:
    """
    Check if the unsigned session key is registered in the database.

    Args:
    - unsigned_session_key (str): The session key to be checked.

    Returns:
    - bool: True if the session key is registered, False otherwise.
    """

    queried_user: Union[User, None] = _get_user_by_session_key(unsigned_session_key)

    if queried_user is None:
        return False

    return True


def _is_fresh_cookie(cookie_expires: str, cookie_max_age: int) -> bool:
    """
    Check if the cookie is fresh based on its expiration time and max age.

    Args:
    - cookie_expires (str): The expiration time of the cookie.
    - cookie_max_age (int): The max age of the cookie.

    Returns:
    - bool: True if the cookie is fresh, False otherwise.

    """

    max_age_delta = datetime.timedelta(seconds=float(cookie_max_age))

    expire_date = datetime.datetime.strptime(
        cookie_expires,
        "%a, %d %b %Y %H:%M:%S %Z",
    )

    expire_date = datetime.datetime.combine(
        expire_date.date(),
        expire_date.time(),
        tzinfo=datetime.UTC,
    )

    cookie_age = datetime.datetime.now(datetime.UTC) - expire_date

    if cookie_age > max_age_delta:
        return False

    return True


def _get_user_by_session_key(unsigned_session_key: str) -> Optional[User]:
    """
    Get the user from the database based on the session key.


    Args:
    - unsigned_session_key (str): The session key to be queried.

    Returns:
    - User or None: The user matching the session key, or None if no match is found.
    """

    with create_local_session() as db_session:

        query_user_by_key: Select[Tuple[User]] = select(User).where(
            User.session_key == unsigned_session_key
        )

        queried_user: Union[Row[User], None] = db_session.execute(
            query_user_by_key
        ).one_or_none()

    if queried_user is None:
        return None

    return queried_user[0]
