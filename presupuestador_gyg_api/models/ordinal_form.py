from sqlalchemy.orm import Mapped, mapped_column

from presupuestador_gyg_api.database.custom_declarative_base import CustomBase


class OrdinalFormCounter(CustomBase):
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
