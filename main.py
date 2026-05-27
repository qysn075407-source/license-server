from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Header, HTTPException, Request
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Base, engine, get_db
from .models import LicenseKey, DeviceActivation, AccessToken, UsedNonce, AuditLog
from .schemas import CreateKeysRequest, CreateKeysResponse, ActivateRequest, SignedTokenResponse, HeartbeatRequest, SignedHeartbeatResponse, BanRequest, UnbindDeviceRequest
from .security import hmac_hash, make_key, make_token, sign_response, load_public_key_pem
from .config import settings

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Kami License System Pro", version="2.0.0")

def client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"

def audit(db: Session, event: str, license_id: int | None = None, device_id: str | None = None, ip: str | None = None, detail: str | None = None):
    db.add(AuditLog(event=event, license_id=license_id, device_id=device_id, ip=ip, detail=detail))

def admin_required(x_admin_token: str | None = Header(default=None)):
    if not x_admin_token or x_admin_token != settings.admin_token:
        raise HTTPException(status_code=401, detail="invalid admin token")

def signed(data: dict) -> dict:
    return sign_response(data)

def mark_expired_if_needed(lic: LicenseKey, db: Session) -> bool:
    if lic.expires_at and datetime.utcnow() >= lic.expires_at and lic.status != "expired":
        lic.status = "expired"
        db.query(AccessToken).filter(AccessToken.license_id == lic.id).update({AccessToken.revoked: True})
        audit(db, "license_expired", lic.id)
        db.commit()
        db.refresh(lic)
    return lic.status == "expired"

def check_and_store_nonce(db: Session, token_or_key: str, nonce: str):
    if len(nonce) < 16:
        raise HTTPException(status_code=400, detail="nonce too short")
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=settings.replay_nonce_ttl_seconds)
    db.query(UsedNonce).filter(UsedNonce.created_at < cutoff).delete()
    nonce_hash = hmac_hash(token_or_key + ":" + nonce)
    exists = db.execute(select(UsedNonce).where(UsedNonce.nonce_hash == nonce_hash)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="replay nonce detected")
    db.add(UsedNonce(nonce_hash=nonce_hash, token_hash=hmac_hash(token_or_key), created_at=now))

@app.get("/health")
def health():
    return {"ok": True, "server_time": datetime.utcnow()}

@app.get("/public-key")
def public_key():
    return {"algorithm": "Ed25519", "public_key_pem": load_public_key_pem()}

@app.post("/admin/keys", response_model=CreateKeysResponse, dependencies=[Depends(admin_required)])
def create_keys(req: CreateKeysRequest, db: Session = Depends(get_db)):
    plain_keys = []
    for _ in range(req.count):
        key = make_key()
        plain_keys.append(key)
        db.add(LicenseKey(
            key_hash=hmac_hash(key),
            plan=req.plan,
            duration_days=req.duration_days,
            max_devices=req.max_devices,
            status="unused",
            note=req.note,
        ))
    db.commit()
    return {"keys": plain_keys}

@app.get("/admin/licenses", dependencies=[Depends(admin_required)])
def list_licenses(db: Session = Depends(get_db)):
    rows = db.execute(select(LicenseKey).order_by(LicenseKey.id.desc()).limit(200)).scalars().all()
    out = []
    for r in rows:
        devices = db.execute(select(DeviceActivation).where(DeviceActivation.license_id == r.id)).scalars().all()
        out.append({
            "id": r.id,
            "key_hash": r.key_hash,
            "plan": r.plan,
            "status": r.status,
            "duration_days": r.duration_days,
            "max_devices": r.max_devices,
            "expires_at": r.expires_at,
            "activated_at": r.activated_at,
            "created_at": r.created_at,
            "devices": [{"device_id": d.device_id, "device_name": d.device_name, "last_seen_at": d.last_seen_at, "is_online": d.is_online, "banned": d.banned, "last_ip": d.last_ip} for d in devices],
        })
    return out

@app.post("/admin/ban", dependencies=[Depends(admin_required)])
def ban_license(req: BanRequest, request: Request, db: Session = Depends(get_db)):
    q = select(LicenseKey)
    if req.license_id:
        q = q.where(LicenseKey.id == req.license_id)
    elif req.key_hash:
        q = q.where(LicenseKey.key_hash == req.key_hash)
    else:
        raise HTTPException(status_code=400, detail="license_id or key_hash required")
    lic = db.execute(q).scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="license not found")
    lic.status = "banned"
    db.query(AccessToken).filter(AccessToken.license_id == lic.id).update({AccessToken.revoked: True})
    audit(db, "license_banned", lic.id, ip=client_ip(request), detail=req.reason)
    db.commit()
    return {"ok": True, "license_id": lic.id, "status": lic.status}

@app.post("/admin/unbind-device", dependencies=[Depends(admin_required)])
def unbind_device(req: UnbindDeviceRequest, request: Request, db: Session = Depends(get_db)):
    dev = db.execute(select(DeviceActivation).where(DeviceActivation.license_id == req.license_id, DeviceActivation.device_id == req.device_id)).scalar_one_or_none()
    if not dev:
        raise HTTPException(status_code=404, detail="device not found")
    db.delete(dev)
    db.query(AccessToken).filter(AccessToken.license_id == req.license_id, AccessToken.device_id == req.device_id).update({AccessToken.revoked: True})
    audit(db, "device_unbound", req.license_id, req.device_id, client_ip(request))
    db.commit()
    return {"ok": True}

@app.post("/activate", response_model=SignedTokenResponse)
def activate(req: ActivateRequest, request: Request, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    ip = client_ip(request)
    check_and_store_nonce(db, req.license_key, req.nonce)
    lic = db.execute(select(LicenseKey).where(LicenseKey.key_hash == hmac_hash(req.license_key))).scalar_one_or_none()
    if not lic:
        audit(db, "activate_invalid_key", device_id=req.device_id, ip=ip)
        db.commit()
        return signed({"ok": False, "action": "exit", "reason": "invalid_license_key", "nonce": req.nonce, "server_time": now, "heartbeat_interval_seconds": settings.heartbeat_interval_seconds, "offline_grace_seconds": settings.offline_grace_seconds})
    mark_expired_if_needed(lic, db)
    if lic.status in {"banned", "expired"}:
        audit(db, "activate_denied", lic.id, req.device_id, ip, lic.status)
        db.commit()
        return signed({"ok": False, "action": "exit", "reason": f"license_{lic.status}", "nonce": req.nonce, "server_time": now, "license_expires_at": lic.expires_at, "heartbeat_interval_seconds": settings.heartbeat_interval_seconds, "offline_grace_seconds": settings.offline_grace_seconds})

    if lic.status == "unused":
        lic.status = "active"
        lic.activated_at = now
        lic.expires_at = now + timedelta(days=lic.duration_days)
        audit(db, "license_first_activated", lic.id, req.device_id, ip)

    existing = db.execute(select(DeviceActivation).where(DeviceActivation.license_id == lic.id, DeviceActivation.device_id == req.device_id)).scalar_one_or_none()
    if existing and existing.banned:
        audit(db, "device_banned_denied", lic.id, req.device_id, ip)
        db.commit()
        return signed({"ok": False, "action": "exit", "reason": "device_banned", "nonce": req.nonce, "server_time": now, "heartbeat_interval_seconds": settings.heartbeat_interval_seconds, "offline_grace_seconds": settings.offline_grace_seconds})
    if not existing:
        used = db.execute(select(func.count()).select_from(DeviceActivation).where(DeviceActivation.license_id == lic.id)).scalar_one()
        if used >= lic.max_devices:
            audit(db, "device_limit_reached", lic.id, req.device_id, ip, f"max={lic.max_devices}")
            db.commit()
            return signed({"ok": False, "action": "exit", "reason": "device_limit_reached", "nonce": req.nonce, "server_time": now, "license_expires_at": lic.expires_at, "heartbeat_interval_seconds": settings.heartbeat_interval_seconds, "offline_grace_seconds": settings.offline_grace_seconds})
        db.add(DeviceActivation(license_id=lic.id, device_id=req.device_id, device_name=req.device_name, first_ip=ip, last_ip=ip, user_agent=request.headers.get("user-agent"), last_seen_at=now, is_online=True))
        audit(db, "device_bound", lic.id, req.device_id, ip)
    else:
        existing.last_seen_at = now
        existing.is_online = True
        existing.last_ip = ip
        existing.user_agent = request.headers.get("user-agent")
        audit(db, "device_reactivated", lic.id, req.device_id, ip)

    token = make_token()
    token_expires_at = min(now + timedelta(seconds=settings.access_token_ttl_seconds), lic.expires_at)
    db.add(AccessToken(token_hash=hmac_hash(token), license_id=lic.id, device_id=req.device_id, expires_at=token_expires_at))
    db.commit()
    return signed({
        "ok": True,
        "action": "continue",
        "access_token": token,
        "token_expires_at": token_expires_at,
        "license_expires_at": lic.expires_at,
        "plan": lic.plan,
        "heartbeat_interval_seconds": settings.heartbeat_interval_seconds,
        "offline_grace_seconds": settings.offline_grace_seconds,
        "nonce": req.nonce,
        "server_time": now,
    })

@app.post("/heartbeat", response_model=SignedHeartbeatResponse)
def heartbeat(req: HeartbeatRequest, request: Request, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    ip = client_ip(request)
    check_and_store_nonce(db, req.access_token, req.nonce)
    tok = db.execute(select(AccessToken).where(AccessToken.token_hash == hmac_hash(req.access_token), AccessToken.device_id == req.device_id)).scalar_one_or_none()
    base = {"nonce": req.nonce, "server_time": now}
    if not tok or tok.revoked:
        audit(db, "heartbeat_bad_token", device_id=req.device_id, ip=ip)
        db.commit()
        return signed({**base, "ok": False, "action": "exit", "reason": "token_revoked_or_invalid"})
    if now >= tok.expires_at:
        tok.revoked = True
        audit(db, "token_expired", tok.license_id, req.device_id, ip)
        db.commit()
        return signed({**base, "ok": False, "action": "relogin", "reason": "token_expired", "token_expires_at": tok.expires_at})

    lic = db.get(LicenseKey, tok.license_id)
    if not lic:
        return signed({**base, "ok": False, "action": "exit", "reason": "license_missing"})
    if mark_expired_if_needed(lic, db):
        audit(db, "heartbeat_license_expired", lic.id, req.device_id, ip)
        db.commit()
        return signed({**base, "ok": False, "action": "exit", "reason": "license_expired", "license_expires_at": lic.expires_at, "token_expires_at": tok.expires_at})
    if lic.status == "banned":
        tok.revoked = True
        audit(db, "heartbeat_license_banned", lic.id, req.device_id, ip)
        db.commit()
        return signed({**base, "ok": False, "action": "exit", "reason": "license_banned", "license_expires_at": lic.expires_at, "token_expires_at": tok.expires_at})

    dev = db.execute(select(DeviceActivation).where(DeviceActivation.license_id == lic.id, DeviceActivation.device_id == req.device_id)).scalar_one_or_none()
    if not dev:
        tok.revoked = True
        audit(db, "heartbeat_unbound_device", lic.id, req.device_id, ip)
        db.commit()
        return signed({**base, "ok": False, "action": "exit", "reason": "device_unbound"})
    if dev.banned:
        tok.revoked = True
        audit(db, "heartbeat_device_banned", lic.id, req.device_id, ip)
        db.commit()
        return signed({**base, "ok": False, "action": "exit", "reason": "device_banned"})

    dev.last_seen_at = now
    dev.is_online = True
    dev.last_ip = ip
    dev.user_agent = request.headers.get("user-agent")
    db.commit()
    return signed({**base, "ok": True, "action": "continue", "reason": None, "license_expires_at": lic.expires_at, "token_expires_at": tok.expires_at})

@app.post("/validate", response_model=SignedHeartbeatResponse)
def validate(req: HeartbeatRequest, request: Request, db: Session = Depends(get_db)):
    return heartbeat(req, request, db)

@app.get("/admin/audit", dependencies=[Depends(admin_required)])
def audit_logs(db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(300)).scalars().all()
    return [{"id": r.id, "event": r.event, "license_id": r.license_id, "device_id": r.device_id, "ip": r.ip, "detail": r.detail, "created_at": r.created_at} for r in rows]

@app.post("/admin/cleanup", dependencies=[Depends(admin_required)])
def cleanup(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    expired = db.query(LicenseKey).filter(LicenseKey.expires_at != None, LicenseKey.expires_at <= now, LicenseKey.status == "active").update({LicenseKey.status: "expired"})
    old_online = db.query(DeviceActivation).filter(DeviceActivation.last_seen_at != None, DeviceActivation.last_seen_at < now - timedelta(seconds=settings.heartbeat_grace_seconds)).update({DeviceActivation.is_online: False})
    revoked_tokens = db.query(AccessToken).filter(AccessToken.expires_at <= now).update({AccessToken.revoked: True})
    old_nonces = db.query(UsedNonce).filter(UsedNonce.created_at < now - timedelta(seconds=settings.replay_nonce_ttl_seconds)).delete()
    db.commit()
    return {"ok": True, "expired_licenses": expired, "offline_devices": old_online, "revoked_tokens": revoked_tokens, "deleted_old_nonces": old_nonces}
