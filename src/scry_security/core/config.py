"""Validated settings; construction has no filesystem or monitoring side effects."""

from pathlib import Path
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Read SCRY_ environment variables, with explicit arguments taking precedence."""

    model_config = SettingsConfigDict(env_prefix="SCRY_", frozen=True)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    data_dir: Path = Path("data")
    api_token: SecretStr | None = None

    @field_validator("data_dir", mode="before")
    @classmethod
    def validate_data_dir(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            raise ValueError("data_dir must not be empty")
        return value

    @field_validator("data_dir")
    @classmethod
    def expand_data_dir(cls, value: Path) -> Path:
        return value.expanduser()
