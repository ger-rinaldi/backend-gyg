from os import getenv
from typing import Union

from itsdangerous import Signer
from itsdangerous.exc import BadSignature


def privilege_based_sign(user_session_salt: str, is_admin: bool) -> str:
    """
    Create a signed token based on the user's privilege level.

    Args:
    - user_session_salt (str): The user session salt.
    - is_admin (bool): A boolean indicating if the user is an admin.

    Returns:
    - str: A signed token containing the user session salt.
    """

    signer: Signer = Signer(secret_key=getenv("SECRET_KEY"))

    if is_admin:
        privilege_based_salt: str = getenv("SECRET_SALT_ADMIN")
    else:
        privilege_based_salt: str = getenv("SECRET_SALT_USER")

    signer.salt = privilege_based_salt.encode("UTF-8")

    return signer.sign(user_session_salt).decode("UTF-8")


def privilege_based_unsign(user_session_key: str) -> Union[str, BadSignature]:
    """
    Unsign a token based on the user's privilege level.

    Args:
    - user_session_key (str): The user session key.

    Returns:
    - str: The user session salt if the key is valid, otherwise raises a BadSignature exception.
    """
    adm_signer: Signer = Signer(
        secret_key=getenv("SECRET_KEY"),
        salt=getenv("SECRET_SALT_ADMIN"),
    )

    usr_signer: Signer = Signer(
        secret_key=getenv("SECRET_KEY"),
        salt=getenv("SECRET_SALT_USER"),
    )

    try:
        return usr_signer.unsign(user_session_key).decode("UTF-8")
    except BadSignature:
        try:
            return adm_signer.unsign(user_session_key).decode("UTF-8")
        except BadSignature:
            raise BadSignature("Invalid user session key")
