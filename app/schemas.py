from datetime import datetime
from pydantic import BaseModel, Field

class CreateKeysRequest(BaseModel):
    count: int = Field(ge=1, le=1000)
    duration_days: int = Field(default=30, ge=1, le=3650)
    max_devices: int = Field(default=1, ge=1, le=20)
    plan: str = "standard"
    note: str | None = None

class CreateKeysResponse(BaseModel):
    keys: list[str]

class ActivateRequest(BaseModel):
    license_key: str
    device_id: str
    device_name: str | None = None
    nonce: str

class SignedTokenResponse(BaseModel):
    ok: bool
    action: str
    access_token: str | None = None
    token_expires_at: datetime | None = None
    license_expires_at: datetime | None = None
    plan: str | None = None
    heartbeat_interval_seconds: int
    offline_grace_seconds: int
    nonce: str
    server_time: datetime
    reason: str | None = None
    signed_at: str | None = None
    signature: str | None = None

class HeartbeatRequest(BaseModel):
    access_token: str
    device_id: str
    nonce: str

class SignedHeartbeatResponse(BaseModel):
    ok: bool
    action: str # continue, exit, relogin
    reason: str | None = None
    license_expires_at: datetime | None = None
    token_expires_at: datetime | None = None
    nonce: str
    server_time: datetime
    signed_at: str | None = None
    signature: str | None = None

class BanRequest(BaseModel):
    key_hash: str | None = None
    license_id: int | None = None
    reason: str | None = None

class UnbindDeviceRequest(BaseModel):
    license_id: int
    device_id: str
