"""Foundation contracts, including both target platform families."""

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from scry_security.core.config import Settings
from scry_security.core.logging import UTCFormatter, configure_logging
from scry_security.core.platform import OperatingSystem, detect_platform
from scry_security.main import main


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("SCRY_LOG_LEVEL", raising=False)
    monkeypatch.delenv("SCRY_DATA_DIR", raising=False)


def test_settings_defaults_and_no_directory_creation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings = Settings()
    assert settings.log_level == "INFO"
    assert settings.data_dir == Path("data")
    assert not (tmp_path / "data").exists()


def test_environment_and_explicit_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SCRY_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("SCRY_DATA_DIR", str(tmp_path / "security data"))
    assert Settings().log_level == "WARNING"
    assert Settings().data_dir == tmp_path / "security data"
    assert Settings(log_level="DEBUG").log_level == "DEBUG"


@pytest.mark.parametrize("field,value", [("log_level", "TRACE"), ("data_dir", " ")])
def test_invalid_settings(field, value):
    with pytest.raises(ValidationError):
        Settings(**{field: value})


@pytest.mark.parametrize(
    "native,expected",
    [
        ("Windows", OperatingSystem.WINDOWS),
        ("Linux", OperatingSystem.LINUX),
        ("Darwin", OperatingSystem.UNSUPPORTED),
        ("", OperatingSystem.UNSUPPORTED),
    ],
)
def test_platform_detection(monkeypatch, native, expected):
    monkeypatch.setattr("scry_security.core.platform.platform.system", lambda: native)
    assert detect_platform().operating_system == expected


def test_logging_is_idempotent_and_preserves_root_handlers():
    root_handlers = list(logging.getLogger().handlers)
    logger = configure_logging("INFO")
    initial_handlers = list(logger.handlers)
    assert configure_logging("DEBUG").handlers == initial_handlers
    assert logger.level == logging.DEBUG
    assert not logger.propagate
    assert logging.getLogger().handlers == root_handlers
    record = logging.LogRecord("test", logging.INFO, "", 1, "hello", (), None)
    record.created = 0
    assert UTCFormatter("%(asctime)sZ", "%Y-%m-%dT%H:%M:%S").format(record) == (
        "1970-01-01T00:00:00Z"
    )


@pytest.mark.parametrize("native,exit_code", [("Windows", 0), ("Linux", 0), ("Darwin", 1)])
def test_check_command(monkeypatch, capsys, native, exit_code):
    monkeypatch.setattr("scry_security.core.platform.platform.system", lambda: native)
    assert main(["--check"]) == exit_code
    output = json.loads(capsys.readouterr().out)
    assert output["collection_enabled"] is False
    assert output["platform_family_supported"] is (exit_code == 0)


def test_invalid_configuration_does_not_echo_values(monkeypatch, capsys):
    monkeypatch.setenv("SCRY_LOG_LEVEL", "sensitive-invalid-value")
    assert main(["--check"]) == 2
    output = capsys.readouterr()
    assert "log_level" in output.err
    assert "sensitive-invalid-value" not in output.err
    assert output.out == ""


def test_help_without_starting_collection(capsys):
    assert main([]) == 0
    assert "--check" in capsys.readouterr().out
