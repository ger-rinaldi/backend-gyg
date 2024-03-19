from pydantic import BaseModel, SecretStr


class User(BaseModel):
    id: int
    name: str
    surname: str
    username: str
    email: str
    password: SecretStr
