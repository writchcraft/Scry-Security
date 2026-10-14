"""Explicit SQLite lifecycle; importing the module never creates a database."""

import os
from pathlib import Path

from sqlalchemy import URL, create_engine, event
from sqlalchemy.orm import sessionmaker

from scry_security.database.models import Base

APPLICATION_ID = 0x53435259  # SCRY, an application marker rather than authentication.


class DatabaseIdentityError(ValueError):
    """Refuse to initialise Scry tables inside an unrelated SQLite database."""


class Database:
    def __init__(self, path: Path):
        if path.is_symlink():
            raise DatabaseIdentityError("Database paths must not be symbolic links")
        path = path.resolve()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        self.engine = create_engine(
            URL.create("sqlite", database=str(path)),
            connect_args={"check_same_thread": False, "autocommit": False},
        )

        @event.listens_for(self.engine, "connect")
        def foreign_keys(connection, _record):
            # Python 3.12+ transaction mode must temporarily allow this PRAGMA.
            previous = connection.autocommit
            connection.autocommit = True
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
            connection.autocommit = previous

        try:
            with self.engine.begin() as connection:
                application_id = connection.exec_driver_sql("PRAGMA application_id").scalar_one()
                tables = set(
                    connection.exec_driver_sql(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).scalars()
                )
                legacy_core = {
                    "hosts",
                    "events",
                    "rules",
                    "alerts",
                    "alert_evidence",
                    "configuration",
                }
                if application_id not in {0, APPLICATION_ID} or (
                    application_id == 0
                    and tables
                    and not (legacy_core.issubset(tables) and tables.issubset(Base.metadata.tables))
                ):
                    raise DatabaseIdentityError(
                        "Selected SQLite file belongs to another application"
                    )
                connection.exec_driver_sql(f"PRAGMA application_id={APPLICATION_ID}")
            Base.metadata.create_all(self.engine)
        except Exception:
            self.engine.dispose()
            raise
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def close(self) -> None:
        self.engine.dispose()
