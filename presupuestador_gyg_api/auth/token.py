from hashlib import sha1
from secrets import token_urlsafe
from typing import Union

from sqlalchemy import update

from presupuestador_gyg_api.auth import sign
from presupuestador_gyg_api.database import session
from presupuestador_gyg_api.models import User


def create_session_token(username: str, is_admin: bool) -> str:
    """
    Create a new session token for the user with the given username and privilege level.

    This function creates a new user session salt, constructs a signed token with
    the user's information, and saves the new session token in the user entity.

    Args:
    - username (str): The user's username.
    - is_admin (bool): A boolean indicating if the user is an admin.

    Returns:
    - str: A signed token containing the user's session information.
    """

    identity_user_info: bytes = _stringify_identity_info(
        username,
        is_admin,
        _get_user_session_salt(username),
    )

    hashed_info: str = _hex_sha1(identity_user_info)

    _update_user_session_key(username, hashed_info)

    return sign.privilege_based_sign(hashed_info, is_admin)


def _get_user_session_salt(username: str) -> str:
    """
    Get or generate a new user session salt.

    Args:
    - username (str): The user's username.

    Returns:
    - str: A random user session salt.
    """

    user_session_salt = token_urlsafe(60)

    _update_user_session_salt(username, user_session_salt)

    return user_session_salt


def _stringify_identity_info(username: str, is_admin: bool, user_salt: str) -> bytes:
    """
    Return a stringified representation of the user's identity.

    Args:
    - username (str): The user's username.
    - is_admin (bool): A boolean indicating if the user is an admin.
    - user_salt (str): The user's session salt.

    Returns:
    - bytes: A byte-encoded representation of the user's identity.
    """

    return f"{username}{is_admin}{user_salt}".encode("UTF-8")


def _hex_sha1(user_identity_string) -> str:
    """
    Return the hexadecimal digest of the SHA1 hash of the given string.

    Args:
    - user_identity_string (str): The string to hash.

    Returns:
    - str: The hexadecimal digest of the SHA1 hash.
    """

    user_session_salt = sha1(user_identity_string)
    return user_session_salt.hexdigest()


def _update_user_session_salt(username: str, user_session_salt: str):
    """
    Update the user's personal session salt in the database.

    Args:
    - username (str): The user's username.
    - user_session_salt (str): The new user session salt.

    Returns:
    - None
    """

    with session.create_local_session() as db_session:
        update_query = (
            update(User)
            .where(User.username == username)
            .values(personal_session_salt=user_session_salt)
        )

        db_session.execute(update_query)
        db_session.commit()


def _update_user_session_key(username: str, user_session_key: str):
    """
    Update the user's session token in the database.

    Args:
    - username (str): The user's username.
    - user_session_key (str): The new user session token.

    Returns:
    - None
    """

    with session.create_local_session() as db_session:
        update_query = (
            update(User)
            .where(User.username == username)
            .values(session_key=user_session_key)
        )

        db_session.execute(update_query)
        db_session.commit()


def is_valid_user_key(cookie_session_key: Union[str, bytes], user: User) -> bool:
    """
    Check if a given user session key is valid by reconstructing the user's session
    salt and comparing the resulting hash with the user's stored session key.

    Args:
    - cookie_session_key (str or bytes): The user's session key.
    - user (User): The user object.

    Returns:
    - bool: True if the user's session key is valid, False otherwise.
    """

    recreated_user_session_key = _hex_sha1(
        _stringify_identity_info(
            user.username, user.is_admin, user.personal_session_salt
        )
    )

    if (
        cookie_session_key == user.session_key
        and cookie_session_key == recreated_user_session_key
    ):
        return True

    return False
