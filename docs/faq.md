# AI Radar — 常见问题

## 使用

**Q：第一次打开提示输入密码？**
A：这是 HTTP Basic Auth。问管理员要 `DASHBOARD_AUTH_USER` + `DASHBOARD_AUTH_PASSWORD`。浏览器记住后就不用再输。

**Q：忘记控制台密码？**
A：找管理员重置 `CONSOLE_PASSWORD` 环境变量。控制台密码是改服务器配置（API key、Feishu webhook）用的，和登录密码是两套。

**Q：「分析启动失败」？**
A：99% 是 LLM API key 没配或额度用完。打开控制台看 `system-health` 状态。

**Q：分析一直转圈不出结果？**
A：单个 LLM 偶发超时。点「内容生产线」找对应 job，状态为 error 时点「重试」。

**Q：文章质量不达标？**
A：审稿 < 7.5 分会进入 `human_review`。可手动点「修订」让 AI 改一版，或者直接编辑后再发布。

**Q：能不能改文章生成风格？**
A：能。编辑 `content-engine/brain/prompts/script_generation.md` 和 `humanize.md`，下次生成生效。

## 发布

**Q：公众号发布需要哪些权限？**
A：需要服务号或认证订阅号的 `app_id` + `app_secret`。个人订阅号目前只能推到草稿箱，不能直接发布。

**Q：除了公众号还支持哪些平台？**
A：当前正式支持公众号草稿箱 + 飞书通知。头条号、知乎、B 站、小红书在路线图上。

## 数据

**Q：数据备份吗？**
A：服务挂的 Docker volume 持久化，重启不丢。每天凌晨 3 点跑 `scripts/backup.sh` 打 tar 包到 `/backup`。

**Q：能导出我的数据吗？**
A：当前 API 都可以拿 JSON。CSV/Excel 导出在 Stage 3 路线图里。

**Q：抓取的第三方热点能转载吗？**
A：参见 [版权说明](./copyright.md)。简单说：标题/链接可以聚合，全文转载需要原站授权。AI 写出的二次创作内容版权归你。

## 安全

**Q：源码会暴露吗？**
A：不会。`/server.py`、`/start.sh`、`/.git/*`、`/Dockerfile` 等返回 404。只服务白名单的静态文件。

**Q：API 会被人乱调吗？**
A：未鉴权请求返回 401。同时有 IP/token 维度的速率限制，超额 429。

**Q：日志会泄露 API key 吗？**
A：不会。错误响应已脱敏文件路径，stack trace 不返回客户端。审计日志只记录 key 名（如 `ANTHROPIC_API_KEY`），不记录值。

**Q：CONSOLE_PASSWORD 强度要求？**
A：必须 ≥ 12 字符，且不在常见弱密码列表（radar2026 / admin / password / 12345678 / qwerty 等）。

## 部署

**Q：怎么部署到自己服务器？**
A：见 [DEPLOY.md](../DEPLOY.md)（部署指南）。

**Q：可以离线运行吗？**
A：可以。LLM 部分需要外网（DeepSeek/Gemini/Claude API），其余功能不依赖外网。完全离线需用本地 LLM 替代（路线图）。

**Q：要多少配置？**
A：2 核 4G 起步够用（个人 / 小团队）；4 核 8G 适合每天 10+ 篇产能。

## 计费

**Q：LLM 一篇文章成本多少？**
A：粗略估算（2026-05 价格）：
- 摘要 / 翻译：DeepSeek，¥0.001 / 次
- 4 模型深度分析：¥0.5-2 / 次
- Claude Opus 写稿：¥2-5 / 篇
- AI 审稿：¥0.3-1 / 次

**总：一篇深度长文约 ¥3-10。**

**Q：每月跑 100 篇要多少钱？**
A：~ ¥300-1000，主要是 Claude Opus 写稿成本。可用 DeepSeek/Gemini 兜底降本。
