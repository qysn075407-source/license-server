import base64, hashlib, hmac, json, os, secrets, string
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .config import settings

ALPHABET = string.ascii_uppercase + string.digits

def hmac_hash(value: str) -> str:
    return hmac.new(settings.key_pepper.encode(), value.encode(), hashlib.sha256).hexdigest()

def make_key(prefix: str = "KM", blocks: int = 4, block_len: int = 5) -> str:
    parts = ["".join(secrets.choice(ALPHABET) for _ in range(block_len)) for _ in range(blocks)]
    return prefix + "-" + "-".join(parts)

def make_token() -> str:
    return secrets.token_urlsafe(32)

def canonical_json(data: dict) -> bytes:
    clean = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode()

def ensure_signing_keys() -> None:
    if os.path.exists(settings.signing_private_key_file) and os.path.exists(settings.signing_public_key_file):
        return
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    with open(settings.signing_private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(settings.signing_public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def load_private_key() -> Ed25519PrivateKey:
    ensure_signing_keys()
    with open(settings.signing_private_key_file, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key_pem() -> str:
    ensure_signing_keys()
    with open(settings.signing_public_key_file, "r", encoding="utf-8") as f:
        return f.read()

def sign_response(data: dict) -> dict:
    private_key = load_private_key()
    payload = dict(data)
    payload.setdefault("signed_at", datetime.utcnow().isoformat())
    sig = private_key.sign(canonical_json(payload))
    payload["signature"] = base64.b64encode(sig).decode()
    return payload

def verify_signature_with_public_key(data: dict, public_pem: str) -> bool:
    sig_b64 = data.get("signature")
    if not sig_b64:
        return False
    public_key = serialization.load_pem_public_key(public_pem.encode())
    if not isinstance(public_key, Ed25519PublicKey):
        return False
    try:
        public_key.verify(base64.b64decode(sig_b64), canonical_json(data))
        return True
    except Exception:
        return False
