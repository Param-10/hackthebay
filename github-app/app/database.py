from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import get_settings


engine = create_engine(
    get_settings().database_url,
    connect_args={"check_same_thread": False},  # SQLite only
)
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
