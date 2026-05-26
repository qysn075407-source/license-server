"""
Client SDK sample for Kami License System Pro.
用途：演示合法软件授权接入。
重点：机器码、nonce、防重放、公钥验签、心跳失败自动退出。
"""
import base64
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_json(data: dict) -> bytes:
    clean = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode()


def verify_signature(data: dict, public_key_pem: str) -> bool:
    sig = data.get("signature")
    if not sig:
        return False
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(public_key, Ed25519PublicKey):
        return False
    try:
        public_key.verify(base64.b64decode(sig), canonical_json(data))
        return True
    except Exception:
        return False


def run_cmd(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2)
        return out.decode(errors="ignore").strip()
    except Exception:
        return ""


def get_machine_fingerprint(app_salt: str = "change-this-per-app") -> str:
    """
    机器码建议：多信息组合 + SHA256，不上传原始硬件信息。
    注意：不同系统权限不同，某些字段可能为空，所以要容错。
    """
    parts = [
        platform.system(),
        platform.machine(),
        platform.node(),
        str(uuid.getnode()),
        socket.gethostname(),
    ]

    system = platform.system().lower()
    if system == "windows":
        parts.append(run_cmd(["wmic", "csproduct", "get", "uuid"]))
        parts.append(run_cmd(["wmic", "baseboard", "get", "serialnumber"]))
        parts.append(run_cmd(["wmic", "cpu", "get", "processorid"]))
    elif system == "linux":
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/board_serial"]:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    parts.append(f.read().strip())
            except Exception:
                pass
    elif system == "darwin":
        parts.append(run_cmd(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]))

    raw = "|".join([p for p in parts if p]) + "|" + app_salt
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class LicenseClient:
    base_url: str
    public_key_pem: str
    device_id: str
    access_token: str | None = None
    heartbeat_interval_seconds: int = 30
    offline_grace_seconds: int = 300

    def _nonce(self) -> str:
        return base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")

    def _post_signed(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = requests.post(self.base_url.rstrip("/") + path, json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("nonce") != payload.get("nonce"):
            raise RuntimeError("nonce mismatch: possible replay/tamper")
        if not verify_signature(data, self.public_key_pem):
            raise RuntimeError("bad server signature: possible fake server/tamper")
        return data

    def activate(self, license_key: str, device_name: str | None = None) -> bool:
        nonce = self._nonce()
        data = self._post_signed("/activate", {
            "license_key": license_key,
            "device_id": self.device_id,
            "device_name": device_name or platform.node(),
            "nonce": nonce,
        })
        if not data.get("ok"):
            print("授权失败:", data.get("reason"))
            return False
        self.access_token = data["access_token"]
        self.heartbeat_interval_seconds = int(data.get("heartbeat_interval_seconds", 30))
        self.offline_grace_seconds = int(data.get("offline_grace_seconds", 300))
        return True

    def heartbeat_once(self) -> bool:
        if not self.access_token:
            raise RuntimeError("not activated")
        nonce = self._nonce()
        data = self._post_signed("/heartbeat", {
            "access_token": self.access_token,
            "device_id": self.device_id,
            "nonce": nonce,
        })
        if data.get("ok") and data.get("action") == "continue":
            return True
        print("授权失效:", data.get("reason"))
        return False

    def heartbeat_loop_or_exit(self):
        """
        放到后台线程也可以。这里为了示例简单，直接阻塞循环。
        连续无法联网超过 offline_grace_seconds，退出。
        """
        last_ok = time.time()
        while True:
            try:
                if not self.heartbeat_once():
                    sys.exit(1)
                last_ok = time.time()
            except Exception as e:
                print("心跳异常:", e)
                if time.time() - last_ok > self.offline_grace_seconds:
                    print("离线超过宽限时间，退出")
                    sys.exit(1)
            time.sleep(self.heartbeat_interval_seconds)


if __name__ == "__main__":
    BASE_URL = "http://127.0.0.1:8000"
    # 推荐生产环境：把 public_key_pem 编译进客户端，而不是运行时从服务器拉取。
    public_key_pem = requests.get(BASE_URL + "/public-key", timeout=10).json()["public_key_pem"]
    device_id = get_machine_fingerprint(app_salt="your-product-name-v1")
    client = LicenseClient(BASE_URL, public_key_pem, device_id)

    key = input("请输入卡密: ").strip()
    if not client.activate(key):
        sys.exit(1)
    print("授权成功，开始心跳")
    client.heartbeat_loop_or_exit()
