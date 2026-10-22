from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    app_name: str = "SecureNet"
    database_path: str = "backend/data/securenet.db"
    cert_dir: str = "backend/certs"
    key_dir: str = "backend/keys"
    max_upload_mb: int = 10
    rate_limit_attempts: int = 5
    rate_limit_window_seconds: int = 60
    allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173,https://localhost:5173,https://127.0.0.1:5173"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def path(self, value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else ROOT / p

settings = Settings()
