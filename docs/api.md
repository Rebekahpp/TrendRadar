# AI Radar — API 文档

> 内部 + 客户用 API。所有路径需要鉴权（HTTP Basic 或 Bearer）。

## 鉴权

两种方式，二选一：

**Basic Auth**
```
curl -u admin:YOUR_PASSWORD https://content.orbitlogic.dev/api/stats
```

**Bearer Token**
```
curl -H "Authorization: Bearer YOUR_TOKEN" https://content.orbitlogic.dev/api/stats
```

未鉴权请求会返回 `401`；服务端未配置鉴权时返回 `503`。

## 速率限制

- 普通接口：10 req/s（默认）
- LLM 接口（analyze / generate-* / translate / fetch-page-text 等）：1 req/s
- 突发上限：30 req

超额返回 `429`，body：`{"error":"rate limit exceeded — please slow down"}`。

可通过环境变量调整：`DASHBOARD_RATE_GENERAL`, `DASHBOARD_RATE_LLM`, `DASHBOARD_RATE_BURST`。

## 公共端点

### GET `/healthz`
健康检查，**不需要鉴权**（供 Coolify/Traefik 探活使用）。
```json
{
  "status": "ok",        // 或 "degraded"
  "uptime_seconds": 12345,
  "db": "ok",
  "llm": "ok",            // "missing" 表示没配 LLM key
  "auth_configured": true,
  "console_password_set": true
}
```

## 读取类（GET）

| Endpoint | 说明 |
|----------|------|
| `/api/stats?date=YYYY-MM-DD` | 当日采集统计（来源、数量） |
| `/api/news?date=YYYY-MM-DD` | 当日热榜聚合 |
| `/api/rss?date=YYYY-MM-DD` | 当日 RSS 抓取 |
| `/api/projects?stage=writing` | 内容生产线项目，按阶段过滤 |
| `/api/project?id=N` | 单个项目详情 |
| `/api/analyses` | 历史分析结果列表 |
| `/api/articles` | 历史文章列表 |
| `/api/analysis-detail?file=PATH` | 分析详情（路径白名单限制） |
| `/api/article-detail?file=PATH` | 文章正文（路径白名单限制） |
| `/api/job?id=JOB_ID` | 后台任务状态 |
| `/api/jobs` | 全部运行中任务 |
| `/api/system-health` | LLM 配置 + 上次扫描状态 |
| `/api/recommendations` | 推荐选题（带跳过状态） |
| `/api/templates` | 公众号排版模板 |
| `/api/analytics/summary` | 整体数据看板 |
| `/api/competitors/*` | 竞品监控数据（timeline / topic-stats / cadence / coverage） |
| `/api/topic-events` | 事件聚类结果 |
| `/api/topic-hits?week=YYYY-MM-DD` | 周话题命中率 |

## 写入类（POST，application/json）

### `/api/analyze`
启动深度分析。
```json
{"topic": "OpenAI 发布 GPT-6", "context": "(可选) 补充背景信息"}
```
返回：`{"job_id":"analysis_...", "status":"started", "topic":"..."}`

### `/api/generate-article`
基于分析结果生成文章。
```json
{"selected_insights":[{...}], "analysis_file":"...", "project_id":N}
```

### `/api/review-article` / `/api/revise-article`
AI 审稿 / 修订。

### `/api/publish-article`
推送到公众号草稿箱。**会写入审计日志。**
```json
{"title":"...", "project_id":N, "platform":"wechat", "dry_run":false}
```

### `/api/save-api-keys`
**需要 console 密码**。**会写入审计日志。**
```json
{"password":"<CONSOLE_PASSWORD>", "anthropic_key":"sk-...", "openai_key":"sk-..."}
```

### `/api/set-feishu-webhook`
设置飞书通知地址。**有 SSRF 防护：仅允许 feishu.cn / larksuite.com**。**会写入审计日志。**

### `/api/fetch-page-text?url=...`（GET）
抓取页面正文供 AI 分析。**有 SSRF 防护：仅允许公网 http/https**。

### `/api/competitors/delete`
删除竞品。**会写入审计日志。**

### LLM 输入长度限制
- `topic` 最大 500 字
- `context` 最大 20,000 字
- `text`（翻译用）最大 30,000 字
- 超出截断尾巴，附加 `...[truncated]` 标记

## 审计日志

数据库表 `audit_log`，记录：
- `save-api-keys` — 哪些 key 被修改
- `set-feishu-webhook` — 启用 / 禁用
- `publish-article` — 发布到哪个平台、草稿 ID
- `competitor.delete` — 删除的竞品 ID

可用 SQL 查询：
```sql
SELECT ts, actor, action, target, detail
FROM audit_log
ORDER BY ts DESC LIMIT 100;
```

## 错误格式

所有错误响应：`{"error":"消息"}`，状态码语义：
- `400` — 参数缺失或非法
- `401` — 未鉴权
- `404` — 路由不存在 / 资源不存在
- `413` — 请求体超过 10MB
- `429` — 速率限制
- `503` — 服务未配置鉴权或健康检查失败
