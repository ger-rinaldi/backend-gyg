from pydantic import BaseModel, EmailStr, Field, SecretStr


class User(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    surname: str = Field(min_length=2, max_length=40)
    username: str = Field(min_length=2, max_length=20)
    email: EmailStr
    password: str = Field(min_length=10, max_length=40)  # type: ignore
    is_admin: bool = Field(default=False)
