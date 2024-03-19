import os

from sqlalchemy.engine import URL, create_engine

DB_CREDENTIALS = {
    "drivername": "mysql+mysqlconnector",
    "username": os.getenv("MYSQL_USERNAME"),
    "password": os.getenv("MYSQL_PASSWORD"),
    "host": os.getenv("MYSQL_HOST"),
    "port": os.getenv("MYSQL_PORT"),
    "database": os.getenv("MYSQL_DATABASE"),
}

DB_URL = URL.create(**DB_CREDENTIALS)

ENGINE = create_engine(DB_URL)
