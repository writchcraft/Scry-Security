"""Private file creation and refusal to initialise unrelated SQLite files."""

import os
import sqlite3
import stat

import pytest
from sqlalchemy import text

from scry_security.database.database import APPLICATION_ID, Database, DatabaseIdentityError


def test_unrelated_database_is_left_unchanged(tmp_path):
    path = tmp_path / "other.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('preserve this')")
    original = path.read_bytes()
    with pytest.raises(DatabaseIdentityError):
        Database(path)
    assert path.read_bytes() == original
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall() == [("unrelated",)]


def test_owned_database_marker_and_recognised_legacy_upgrade(tmp_path):
    path = tmp_path / "scry.sqlite"
    database = Database(path)
    with database.sessions() as session:
        assert session.scalar(text("PRAGMA application_id")) == APPLICATION_ID
    database.close()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA application_id=0")
    upgraded = Database(path)
    try:
        with upgraded.sessions() as session:
            assert session.scalar(text("PRAGMA application_id")) == APPLICATION_ID
    finally:
        upgraded.close()


@pytest.mark.skipif(os.name == "nt", reason="Unix mode bits do not represent Windows ACLs")
def test_new_database_has_private_mode_even_in_an_existing_directory(tmp_path):
    path = tmp_path / "private.sqlite"
    database = Database(path)
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        database.close()
