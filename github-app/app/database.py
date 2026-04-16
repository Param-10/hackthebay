from sqlalchemy import create_engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import get_settings

database_url = get_settings().database_url
backend = make_url(database_url).get_backend_name()
engine_kwargs = {"pool_pre_ping": True}
if backend == "sqlite":
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(database_url, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app import models  # noqa: F401 – ensure models are registered
    Base.metadata.create_all(bind=engine)
