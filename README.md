# Kami License System Pro v2

合法软件授权/会员兑换用途的卡密系统。v2 增强了防共享、防重放、防伪造返回和风控审计。

## 已实现能力

- 管理员批量发卡
- 卡密 HMAC 哈希入库，不保存明文卡密
- 一卡一机 / 一卡多机数量限制
- 机器码 device_id 绑定
- 到期自动失效
- 心跳验证，到期/封禁/解绑后客户端退出
- access_token 短期有效
- nonce 防重放
- Ed25519 服务端响应签名
- 客户端公钥验签示例
- 设备在线/离线状态
- 设备解绑
- 卡密封禁
- 审计日志
- Docker 部署

## 启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

接口文档：

```text
http://127.0.0.1:8000/docs
```

首次启动会自动生成：

```text
ed25519_private.pem
ed25519_public.pem
```

私钥只放服务器。客户端只内置公钥。

## 生成卡密

```bash
curl -X POST http://127.0.0.1:8000/admin/keys \
  -H 'X-Admin-Token: change-me-admin-token-long-random' \
  -H 'Content-Type: application/json' \
  -d '{"count":10,"duration_days":30,"max_devices":1,"plan":"vip"}'
```

## 激活

```bash
curl -X POST http://127.0.0.1:8000/activate \
  -H 'Content-Type: application/json' \
  -d '{"license_key":"KM-XXXXX-XXXXX-XXXXX-XXXXX","device_id":"device-001","device_name":"PC","nonce":"random-string-at-least-16"}'
```

成功返回会包含：

```json
{
  "ok": true,
  "action": "continue",
  "access_token": "...",
  "license_expires_at": "...",
  "nonce": "random-string-at-least-16",
  "signature": "..."
}
```

客户端必须检查：

```text
1. nonce 是否和请求一致
2. signature 是否能用内置公钥验签
3. ok/action 是否允许继续
```

## 心跳

```bash
curl -X POST http://127.0.0.1:8000/heartbeat \
  -H 'Content-Type: application/json' \
  -d '{"access_token":"TOKEN","device_id":"device-001","nonce":"another-random-string-at-least-16"}'
```

响应规则：

```json
{"ok":true,"action":"continue"}
```

继续运行。

```json
{"ok":false,"action":"exit","reason":"license_expired"}
```

立即退出或锁定核心功能。

```json
{"ok":false,"action":"relogin","reason":"token_expired"}
```

要求重新激活/登录。

## 客户端接入

示例在：

```text
client_sdk/client.py
```

测试运行：

```bash
python client_sdk/client.py
```

生产建议：

```text
把 /public-key 返回的 public_key_pem 固定写进客户端
不要每次运行都从服务器获取公钥
否则中间人可替换公钥
```

## 管理接口

查看卡密和设备：

```bash
curl http://127.0.0.1:8000/admin/licenses \
  -H 'X-Admin-Token: change-me-admin-token-long-random'
```

封禁卡密：

```bash
curl -X POST http://127.0.0.1:8000/admin/ban \
  -H 'X-Admin-Token: change-me-admin-token-long-random' \
  -H 'Content-Type: application/json' \
  -d '{"license_id":1,"reason":"abuse"}'
```

解绑设备：

```bash
curl -X POST http://127.0.0.1:8000/admin/unbind-device \
  -H 'X-Admin-Token: change-me-admin-token-long-random' \
  -H 'Content-Type: application/json' \
  -d '{"license_id":1,"device_id":"device-001"}'
```

查看审计日志：

```bash
curl http://127.0.0.1:8000/admin/audit \
  -H 'X-Admin-Token: change-me-admin-token-long-random'
```

清理过期 token、过期卡密、离线设备、旧 nonce：

```bash
curl -X POST http://127.0.0.1:8000/admin/cleanup \
  -H 'X-Admin-Token: change-me-admin-token-long-random'
```

生产环境建议 cron 每分钟调用一次。

## Docker

```bash
cp .env.example .env
docker compose up --build
```

## 安全强度说明

这版可以明显增强：

```text
一卡多机共享
抓包重放旧心跳
伪造服务端通过响应
到期后继续联网使用
后台封禁后继续使用
```

仍然不能绝对防：

```text
专业逆向 patch 客户端
把客户端判断逻辑改成永远通过
完全离线破解
```

真正高强度方案：

```text
关键功能服务端化
客户端只做 UI 和调用
核心配置/模型/资源动态下发
多处授权检查
客户端混淆/加壳/反调试
HTTPS 强制证书校验或证书固定
```
