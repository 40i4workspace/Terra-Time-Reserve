from functools import lru_cache
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = Field(alias="SUPABASE_DATABASE_URL")
    supabase_url: str = Field(alias="SUPABASE_URL")
    supabase_jwt_secret: SecretStr = Field(alias="SUPABASE_JWT_SECRET")
    admin_password_seed: SecretStr = Field(alias="ADMIN_PASSWORD_SEED")
    admin_jwt_secret: SecretStr = Field(alias="ADMIN_JWT_SECRET")
    admin_username: str = "root"
    admin_password_period_seconds: int = 900
    admin_password_digits: int = 12
    certificate_issuer: str = "terra-vault"
    certificate_signing_key: SecretStr = Field(alias="CERTIFICATE_SIGNING_KEY")
    baas_data_key: SecretStr | None = Field(default=None, alias="BAAS_DATA_KEY")
    # JSON map of partner slug to a webhook HMAC secret; keep in a secret manager.
    baas_webhook_secrets: SecretStr | None = Field(default=None, alias="BAAS_WEBHOOK_SECRETS")

    @field_validator("admin_password_seed", "admin_jwt_secret", "certificate_signing_key")
    @classmethod
    def minimum_secret_length(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("must be at least 32 characters")
        return value

@lru_cache
def get_settings() -> Settings:
    return Settings()
