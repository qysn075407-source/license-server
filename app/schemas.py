from datetime import datetime
from pydantic import BaseModel, Field, model_validator

class CreateKeysRequest(BaseModel):
    count: int = Field(ge=1, le=1000)
    duration_hours: int | None = Field(default=None, ge=1, le=168)
    duration_seconds: int | None = Field(default=None, ge=3600, le=604800)
    duration_days: int | None = Field(default=None, ge=1, le=7)
    max_devices: int = Field(default=1, ge=1, le=20)
    plan: str = Field(default="standard", max_length=64)
    note: str | None = None

    @model_validator(mode="after")
    def normalize_duration(self):
        if self.duration_seconds is None:
            if self.duration_hours is not None:
                self.duration_seconds = self.duration_hours * 3600
            elif self.duration_days is not None:
                self.duration_seconds = self.duration_days * 86400
            else:
                self.duration_seconds = 24 * 3600
        if self.duration_seconds < 3600 or self.duration_seconds > 604800:
            raise ValueError("duration must be between 1 hour and 7 days")
        self.duration_hours = max(1, round(self.duration_seconds / 3600))
        self.duration_days = max(1, round(self.duration_seconds / 86400))
        return self

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
