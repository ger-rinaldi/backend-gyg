from sqlalchemy.orm import sessionmaker

from presupuestador_gyg_api.database.engine import ENGINE

create_local_session = sessionmaker(autoflush=False, autocommit=False, bind=ENGINE)
