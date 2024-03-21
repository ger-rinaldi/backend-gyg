from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from presupuestador_gyg_api.database.custom_declarative_base import CustomBase


class User(CustomBase):

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(40))
    surname: Mapped[str] = mapped_column(String(40))
    username: Mapped[str] = mapped_column(String(20), unique=True)
    email: Mapped[str] = mapped_column(String(250), unique=True)
    password_hash: Mapped[str] = mapped_column(String(60))
    session_key: Mapped[str] = mapped_column(String(80), default="no_session")
    personal_session_salt: Mapped[str] = mapped_column(String(80), default="no_session")
    is_admin: Mapped[bool] = mapped_column(default=False)
