from sqlalchemy import create_engine, inspect
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
    if inspect(engine).has_table("scan_runs"):
        required = {"dedupe_key", "locked_until", "worker_id", "attempts", "available_at"}
        columns = {column["name"] for column in inspect(engine).get_columns("scan_runs")}
        indexes = inspect(engine).get_indexes("scan_runs")
        has_identity = any(index["unique"] and index["column_names"] == ["dedupe_key"] for index in indexes)
        if not required.issubset(columns) or not has_identity:
            raise RuntimeError("Database migration required: stop old processes and run python -m app.migrate")
    Base.metadata.create_all(bind=engine)
