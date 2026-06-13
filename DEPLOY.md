# AI Radar — 部署 / 升级指南

> 适用版本：Stage 1 + Stage 2 安全加固版（2026-05-12）

## 一、升级流程（已有 Coolify 部署）

### 1. 把代码推上去
本仓库 master 分支已包含所有 Stage 1+2 改动：
```bash
git push deploy master      # → ghcr.io/rebekahpp/ai-radar:latest
```
Coolify 监听到镜像更新会自动拉取。

### 2. 在 Coolify 添加环境变量（**关键**）

进入 Coolify → AI Radar 服务 → Environment Variables，添加：

```env
# ====== 鉴权（必设其一）======
DASHBOARD_AUTH_USER=admin
DASHBOARD_AUTH_PASSWORD=<生成强随机，>=20 字符>
# 或者
DASHBOARD_BEARER_TOKEN=<生成强随机，>=32 字符>

# ====== 控制台密码（必设）======
CONSOLE_PASSWORD=<生成强随机，>=12 字符，不能是 radar2026 / admin / 12345678 等弱密码>

# ====== CORS / 安全限制 ======
DASHBOARD_ALLOWED_ORIGINS=https://content.orbitlogic.dev
DASHBOARD_MAX_BODY_SIZE=10485760

# ====== 速率限制（可选，留默认即可）======
DASHBOARD_RATE_GENERAL=10
DASHBOARD_RATE_LLM=1
DASHBOARD_RATE_BURST=30

# ====== LLM 输入长度限制（可选）======
DASHBOARD_LLM_TOPIC_MAX=500
DASHBOARD_LLM_CONTEXT_MAX=20000
DASHBOARD_LLM_TEXT_MAX=30000

# ====== Dashboard URL（飞书通知用）======
DASHBOARD_URL=https://content.orbitlogic.dev
```

**生成强随机字符串**：
```bash
openssl rand -base64 32
# 或
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. 重新部署
点 Coolify 的「Redeploy」按钮 → 等容器健康检查通过（30 秒）。

### 4. 验收（黑盒，6 行 curl）

```bash
URL="https://content.orbitlogic.dev"
USER="admin"; PWD="<你设的密码>"

# 1. 源码不再裸奔
curl -o /dev/null -s -w "%{http_code}\n" $URL/server.py        # 期望 404
curl -o /dev/null -s -w "%{http_code}\n" $URL/start.sh         # 期望 404

# 2. 无鉴权访问 API 应被拒
curl -o /dev/null -s -w "%{http_code}\n" $URL/api/stats        # 期望 401

# 3. 带凭证访问 API 应通过
curl -u "$USER:$PWD" -o /dev/null -s -w "%{http_code}\n" $URL/api/stats   # 期望 200

# 4. 健康检查不需要鉴权
curl -s $URL/healthz       # 期望 JSON 含 status:ok

# 5. 安全响应头
curl -I $URL/ 2>/dev/null | grep -iE "strict-transport|x-frame|content-security"

# 6. SSRF 被拦
curl -u "$USER:$PWD" "$URL/api/fetch-page-text?url=http://127.0.0.1/" 
# 期望: {"error":"url not allowed"}
```

7 条全部符合预期 ⇒ 部署成功。

## 二、新部署（从零）

### 1. 基础环境
- 1 台 Linux 服务器（建议 4 核 8G，最低 2 核 4G）
- 已装 Docker + Docker Compose
- 已绑域名 + SSL（Cloudflare / Caddy / Traefik 均可）

### 2. 准备数据卷
```bash
docker volume create ai-radar-output
docker volume create ai-radar-content
```

### 3. 准备环境文件
复制 `docker/.env.example` → `docker/.env`，填入所有 LLM key 和上面列出的安全变量。

### 4. 启动
```bash
cd docker
docker compose -f docker-compose.prod.yml up -d
```

### 5. 验收
跑上面「黑盒 6 行 curl」。

### 6. 配置反向代理
让外网通过 HTTPS 访问 `:9090`。Cloudflare Tunnel / Traefik / Caddy 都可。例：
```caddy
content.orbitlogic.dev {
  reverse_proxy localhost:9090
}
```

## 三、备份

容器内已经有 `/app/scripts/backup.sh`，可手动跑：
```bash
docker exec ai-radar /app/scripts/backup.sh
```

设 cron（host 上）：
```cron
0 3 * * * docker exec ai-radar /app/scripts/backup.sh >> /var/log/ai-radar-backup.log 2>&1
```

备份保留 14 天，可改 `RETENTION_DAYS` 环境变量。

## 四、升级注意事项

### 第一次部署 Stage 1+2 版本时
- **必须**在重新部署前设好 `DASHBOARD_AUTH_*` + `CONSOLE_PASSWORD` 环境变量
- 否则启动时只会打 `[SECURITY]` 警告，不会自动阻塞服务

### 已有用户被踢出
- 前端 Basic Auth 弹窗会弹给所有用户。把账户密码发给他们就行
- 如果忘记设过密码，看 docker logs 找 `[SECURITY] DASHBOARD_AUTH_*` 警告

### 速率限制误伤
- 默认 10 req/s 是宽松值。如果有人复诉「请求被拒」，先看 docker logs 找 429
- 可调高：`DASHBOARD_RATE_GENERAL=20`

## 五、回滚

```bash
# 切回上一镜像
docker compose -f docker-compose.prod.yml down
docker pull ghcr.io/rebekahpp/ai-radar:<previous-sha>
docker tag ghcr.io/rebekahpp/ai-radar:<previous-sha> ghcr.io/rebekahpp/ai-radar:latest
docker compose -f docker-compose.prod.yml up -d
```

数据卷不受镜像版本影响，回滚后数据完整。

## 六、监控建议

- **/healthz** 接 Coolify / Uptime Kuma / Pingdom 探活，5 分钟一次
- **docker logs** 关注 `[SECURITY]`、`[AUDIT]`、`[backup]` 三类标签
- **audit_log 表** 周报：
  ```sql
  SELECT action, COUNT(*) FROM audit_log
  WHERE ts > date('now', '-7 days')
  GROUP BY action;
  ```

## 七、常见坑

| 现象 | 原因 | 解法 |
|------|------|------|
| 容器一直 unhealthy | /healthz 返回 503 | 看 docker logs，多半是 DB 文件没挂载或 LLM 全部没配 |
| 浏览器一直问账号密码 | Basic Auth 输错了 | 清缓存 (Cmd+Shift+Del) 重输 |
| 所有 API 都 401 | 环境变量没设 | 看 docker logs 找 `[SECURITY]` 警告 |
| `/api/fetch-page-text` 报「url not allowed」| 输的是内网 IP 或非 https | 这是预期行为 |
| 飞书 webhook 拒绝 | 不在 feishu.cn/larksuite.com 域 | 这是预期行为 |
| 429 频繁 | 触发速率限制 | 调高 `DASHBOARD_RATE_GENERAL` 或停止脚本刷接口 |
