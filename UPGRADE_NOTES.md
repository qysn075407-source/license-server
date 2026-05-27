# Kami License System v2.1 升级说明

- 管理后台 `admin.html` 支持 1 小时到 7 天任意时长。
- `/admin/keys` 支持 `duration_seconds`、`duration_hours`，并兼容旧的 `duration_days`。
- 激活时使用 `duration_seconds` 精确计算到期时间。
- `/admin/licenses` 新增返回 `duration_seconds`、`duration_hours`、`duration_label`。
- 已加入 CORS 中间件，浏览器本地打开 `admin.html` 也能请求接口。
- 启动时会自动给旧数据库补充 `license_keys.duration_seconds` 字段。

部署后打开 `admin.html`，填写服务器地址和管理员 Token 即可使用新版后台。
