from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    admin_token: str = "change-me-admin-token-long-random"
    key_pepper: str = "change-me-key-pepper-long-random"
    database_url: str = "sqlite:///./license.db"
    access_token_ttl_seconds: int = 86400
    heartbeat_interval_seconds: int = 30
    heartbeat_grace_seconds: int = 120
    offline_grace_seconds: int = 300
    replay_nonce_ttl_seconds: int = 300
    signing_private_key_file: str = "./ed25519_private.pem"
    signing_public_key_file: str = "./ed25519_public.pem"

    class Config:
        env_file = ".env"

settings = Settings()
