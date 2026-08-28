"""AI Radar Dashboard - AI 资讯仪表盘 + 内容生产平台
读取 TrendRadar 的 SQLite 数据，提供 JSON API + 前端页面。
支持多模型分析、文章生成、AI 审核等内容生产功能。
"""
import json
import sqlite3
import os
import sys
import glob
import time
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Content-engine root: env var (Docker) or local dev fallback
CE_ROOT = os.environ.get("CONTENT_ENGINE_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "content-engine"))
CE_ROOT = os.path.abspath(CE_ROOT)
sys.path.insert(0, CE_ROOT)

# Load .env file if exists
_env_path = os.path.join(CE_ROOT, ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _ef:
        for _line in _ef:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                _v = _v.strip().strip('"').strip("'")
                if _k.strip() not in os.environ:
                    os.environ[_k.strip()] = _v

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "output"))
DASHBOARD_DIR = os.path.dirname(__file__)
PORT = int(os.environ.get("PORT", 9090))

# ============================================================================
# Sentry error monitoring (Stage 2.6, 2026-05-16)
# 配置：SENTRY_BACKEND_DSN / SENTRY_ENVIRONMENT / SENTRY_RELEASE
# 未设 DSN 时完全跳过初始化（不引入运行时开销）
# ============================================================================
_SENTRY_DSN = os.environ.get("SENTRY_BACKEND_DSN", "").strip()
_SENTRY_ENV = os.environ.get("SENTRY_ENVIRONMENT", "production")
_SENTRY_RELEASE = os.environ.get("SENTRY_RELEASE", "ai-radar@stage2.6")
_SENTRY_TRACES_RATE = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.05"))

_SENTRY_SCRUB_KEYS = {
    "password", "pwd", "secret", "token", "api_key", "apikey",
    "anthropic_key", "openai_key", "airouter_key", "deepseek_key",
    "gemini_key", "tokenkey", "wechat_app_secret", "app_secret",
    "console_password", "dashboard_auth_password", "dashboard_bearer_token",
    "authorization", "cookie", "set-cookie", "x-api-key",
}


def _sentry_before_send(event, hint):
    """脱敏：移除请求头/body/breadcrumb 中的敏感字段。"""
    def _scrub_dict(d):
        if not isinstance(d, dict):
            return
        for k in list(d.keys()):
            kl = str(k).lower()
            if any(s in kl for s in _SENTRY_SCRUB_KEYS):
                d[k] = "[scrubbed]"
            elif isinstance(d[k], dict):
                _scrub_dict(d[k])
    try:
        req = event.get("request", {})
        _scrub_dict(req.get("headers"))
        _scrub_dict(req.get("env"))
        _scrub_dict(req.get("cookies"))
        data = req.get("data")
        if isinstance(data, dict):
            _scrub_dict(data)
        for bc in event.get("breadcrumbs", {}).get("values", []) or []:
            _scrub_dict(bc.get("data"))
        # 去掉绝对路径
        for ex in event.get("exception", {}).get("values", []) or []:
            for frame in (ex.get("stacktrace", {}) or {}).get("frames", []) or []:
                if frame.get("filename"):
                    frame["filename"] = frame["filename"].replace(CE_ROOT, "[CE]").replace(
                        os.path.dirname(__file__), "[DASH]")
    except Exception:
        pass
    return event


if _SENTRY_DSN:
    try:
        import sentry_sdk
        sentry_sdk.init(
            dsn=_SENTRY_DSN,
            environment=_SENTRY_ENV,
            release=_SENTRY_RELEASE,
            send_default_pii=False,
            traces_sample_rate=_SENTRY_TRACES_RATE,
            max_breadcrumbs=50,
            before_send=_sentry_before_send,
        )
        print(f"[SENTRY] backend initialized env={_SENTRY_ENV} release={_SENTRY_RELEASE} traces={_SENTRY_TRACES_RATE}", flush=True)
    except ImportError:
        print("[SENTRY] sentry-sdk not installed, monitoring disabled", flush=True)
        sentry_sdk = None
    except Exception as e:
        print(f"[SENTRY] init failed: {e}", flush=True)
        sentry_sdk = None
else:
    sentry_sdk = None
    print("[SENTRY] backend disabled (SENTRY_BACKEND_DSN not set)", flush=True)


def _sentry_capture(exc, **tags):
    """在被 try/except 吞掉的关键路径手动上报。Sentry 未启用时静默忽略。"""
    if sentry_sdk is None:
        return
    try:
        with sentry_sdk.push_scope() as scope:
            for k, v in tags.items():
                scope.set_tag(k, str(v)[:200])
            sentry_sdk.capture_exception(exc)
    except Exception:
        pass


# ============================================================================
# Security stage 1 (2026-05-12): auth / CORS / SSRF / file disclosure
# 配置方式（环境变量）：
#   DASHBOARD_AUTH_USER + DASHBOARD_AUTH_PASSWORD   HTTP Basic 凭证
#   DASHBOARD_BEARER_TOKEN                          Bearer token（任选其一）
#   DASHBOARD_ALLOWED_ORIGINS                       CORS 白名单，逗号分隔
#   DASHBOARD_MAX_BODY_SIZE                         POST body 上限，默认 10MB
#   CONSOLE_PASSWORD                                控制台密码（必须设置）
# ============================================================================
import base64 as _b64
import hmac as _hmac
import ipaddress as _ipaddress
import socket as _socket
import tempfile as _tempfile
from urllib.parse import urlparse as _sec_urlparse

_AUTH_USER = os.environ.get("DASHBOARD_AUTH_USER", "")
_AUTH_PASSWORD = os.environ.get("DASHBOARD_AUTH_PASSWORD", "")
_BEARER_TOKEN = os.environ.get("DASHBOARD_BEARER_TOKEN", "")
_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("DASHBOARD_ALLOWED_ORIGINS", "").split(",") if o.strip()]
_MAX_BODY_SIZE = int(os.environ.get("DASHBOARD_MAX_BODY_SIZE", str(10 * 1024 * 1024)))
_CONSOLE_PASSWORD = os.environ.get("CONSOLE_PASSWORD", "")
_AUTH_CONFIGURED = bool(_BEARER_TOKEN or (_AUTH_USER and _AUTH_PASSWORD))

if not _AUTH_CONFIGURED:
    print("[SECURITY] DASHBOARD_AUTH_USER+DASHBOARD_AUTH_PASSWORD or DASHBOARD_BEARER_TOKEN not set — /api/* will return 503", flush=True)
if not _CONSOLE_PASSWORD:
    print("[SECURITY] CONSOLE_PASSWORD not set — console operations (save-api-keys / set-feishu-webhook / verify-console) disabled", flush=True)

# 静态文件白名单：默认 SimpleHTTPRequestHandler 会服务目录下所有文件
_STATIC_WHITELIST = {"/", "/index.html", "/favicon.svg", "/robots.txt"}

# /api/analysis-detail 和 /api/article-detail 只允许这些前缀
_ANALYSIS_STORE = os.path.realpath(os.path.join(CE_ROOT, "content-data", "analysis"))
_ARTICLE_STORE = os.path.realpath(os.path.join(CE_ROOT, "content-data", "articles"))
# 容器内同一卷可能挂载到多个路径（/app/content-engine/content-data 和 /data/content-data）
# 两个路径都必须允许，否则旧 DB 记录的文件路径会被安全检查拦住
_ALLOWED_DETAIL_PREFIXES = [_ANALYSIS_STORE, _ARTICLE_STORE]
_ALT_DATA_ROOT = "/data/content-data"
if os.path.isdir(_ALT_DATA_ROOT):
    _ALLOWED_DETAIL_PREFIXES.append(os.path.realpath(os.path.join(_ALT_DATA_ROOT, "analysis")))
    _ALLOWED_DETAIL_PREFIXES.append(os.path.realpath(os.path.join(_ALT_DATA_ROOT, "articles")))
_FORBIDDEN_DETAIL_EXTS = {".env", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".py", ".sh", ".db", ".sqlite", ".pem", ".key", ".crt", ".pfx"}

# 图片存储目录
_IMAGE_STORE = os.path.join(CE_ROOT, "content-data", "images")


def _generate_and_embed_images(article_content: str) -> tuple:
    """Generate images for [IMAGE: ...] placeholders and embed URLs into markdown.

    Returns (updated_content, image_results_list).
    """
    try:
        from article.image_gen import generate_article_images
        import re as _re
        image_results = generate_article_images(article_content, max_images=4)
        if not image_results:
            return article_content, []

        content = article_content
        for img in image_results:
            if "filename" in img and "description" in img:
                desc_escaped = _re.escape(img["description"])
                pattern = r'\[IMAGE:\s*' + desc_escaped + r'\]'
                replacement = '![{}](/api/article-image?file={})'.format(
                    img["description"], img["filename"]
                )
                content = _re.sub(pattern, replacement, content, count=1)

        successful = [i for i in image_results if "filename" in i]
        failed = [i for i in image_results if "error" in i]
        print(f"[ImageGen] {len(successful)} images generated, {len(failed)} failed")
        return content, image_results
    except Exception as e:
        print(f"[ImageGen] Failed to generate images: {e}")
        return article_content, [{"error": str(e)}]

# SSRF 防护：内网 / 链路本地 / 保留段
_PRIVATE_NETS = [
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("169.254.0.0/16"),
    _ipaddress.ip_network("100.64.0.0/10"),
    _ipaddress.ip_network("0.0.0.0/8"),
    _ipaddress.ip_network("::1/128"),
    _ipaddress.ip_network("fc00::/7"),
    _ipaddress.ip_network("fe80::/10"),
]


def _is_private_or_invalid_url(url: str) -> bool:
    """SSRF 检查。返回 True 表示拒绝。仅允许 http/https 公网地址。"""
    if not url:
        return True
    try:
        parsed = _sec_urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return True
        host = parsed.hostname
        if not host:
            return True
        # 直接 IP
        try:
            ip = _ipaddress.ip_address(host)
            return any(ip in net for net in _PRIVATE_NETS)
        except ValueError:
            pass
        # 解析所有 A/AAAA 记录
        try:
            infos = _socket.getaddrinfo(host, None)
        except Exception:
            return True
        for info in infos:
            addr = info[4][0].split("%")[0]
            try:
                ip = _ipaddress.ip_address(addr)
                if any(ip in net for net in _PRIVATE_NETS):
                    return True
            except ValueError:
                continue
        return False
    except Exception:
        return True


def _atomic_write_text(path: str, content: str):
    """原子写入文本：tempfile → fsync → os.replace。崩溃不损坏目标文件。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = _tempfile.mkstemp(prefix=".tmp_", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _is_safe_detail_path(fpath: str) -> bool:
    """analysis-detail / article-detail 的路径白名单：必须落在 analysis/articles 子目录里 + 安全扩展名。"""
    if not fpath:
        return False
    real = os.path.realpath(fpath)
    if not any(real.startswith(p + os.sep) or real == p for p in _ALLOWED_DETAIL_PREFIXES):
        return False
    ext = os.path.splitext(real)[1].lower()
    if ext in _FORBIDDEN_DETAIL_EXTS:
        return False
    return True


# ============================================================================
# Stage 2 hardening (2026-05-12): rate limit / audit log / weak password warn / LLM caps
# ============================================================================
import threading as _sec_thr

# ---- 1. Weak password warning at boot ----
_WEAK_PASSWORDS = {
    "radar2026", "admin", "admin123", "password", "12345678", "qwerty",
    "test", "demo", "root", "letmein", "changeme", "123456", "111111",
}

def _check_password_strength():
    issues = []
    if _AUTH_PASSWORD and (len(_AUTH_PASSWORD) < 12 or _AUTH_PASSWORD.lower() in _WEAK_PASSWORDS):
        issues.append("DASHBOARD_AUTH_PASSWORD too weak (>=12 chars, not in common list)")
    if _BEARER_TOKEN and len(_BEARER_TOKEN) < 24:
        issues.append("DASHBOARD_BEARER_TOKEN too short (>=24 chars recommended)")
    if _CONSOLE_PASSWORD and (len(_CONSOLE_PASSWORD) < 12 or _CONSOLE_PASSWORD.lower() in _WEAK_PASSWORDS):
        issues.append("CONSOLE_PASSWORD too weak (>=12 chars, not in common list)")
    for m in issues:
        print(f"[SECURITY] {m}", flush=True)

_check_password_strength()

# ---- 2. Token-bucket rate limit per client (IP or token) ----
_rate_state = {}
_rate_lock = _sec_thr.Lock()
_RATE_GENERAL = float(os.environ.get("DASHBOARD_RATE_GENERAL", "10"))   # req/s
_RATE_LLM = float(os.environ.get("DASHBOARD_RATE_LLM", "1"))             # req/s
_RATE_BURST = float(os.environ.get("DASHBOARD_RATE_BURST", "30"))        # burst
_LLM_PATHS = {
    "/api/analyze", "/api/generate-article", "/api/review-article", "/api/revise-article",
    "/api/generate-brief", "/api/generate-briefs-batch", "/api/translate",
    "/api/video/generate-script", "/api/video/script-from-article",
    "/api/fetch-page-text", "/api/repurpose", "/api/generate-comments",
    "/api/scan-topics", "/api/competitors/scan",
}

def _rate_allow(client_id: str, path: str) -> bool:
    """Token bucket。LLM 路径限速更严。client_id 不存在时按 IP 计。"""
    now = time.time()
    rate = _RATE_LLM if path in _LLM_PATHS else _RATE_GENERAL
    with _rate_lock:
        st = _rate_state.get(client_id)
        if st is None:
            st = {"tokens": _RATE_BURST, "ts": now}
            _rate_state[client_id] = st
        elapsed = now - st["ts"]
        st["tokens"] = min(_RATE_BURST, st["tokens"] + elapsed * rate)
        st["ts"] = now
        if st["tokens"] < 1:
            return False
        st["tokens"] -= 1
        # 简单 GC：超过 1000 条记录，淘汰最旧
        if len(_rate_state) > 1000:
            try:
                oldest = min(_rate_state.items(), key=lambda kv: kv[1]["ts"])[0]
                _rate_state.pop(oldest, None)
            except ValueError:
                pass
        return True


# ---- 2b. Login brute-force protection (per IP) ----
_login_attempts = {}  # {ip: {"count": int, "first_at": float, "locked_until": float}}
_login_lock = _sec_thr.Lock()
_LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
_LOGIN_WINDOW = float(os.environ.get("LOGIN_WINDOW", "60"))    # seconds
_LOGIN_LOCKOUT = float(os.environ.get("LOGIN_LOCKOUT", "300")) # 5 min lockout

def _login_check(ip: str) -> tuple:
    """检查 IP 是否可以尝试登录。返回 (allowed, remaining_seconds)。"""
    now = time.time()
    with _login_lock:
        rec = _login_attempts.get(ip)
        if rec is None:
            return True, 0
        # 锁定期间
        if rec.get("locked_until", 0) > now:
            return False, int(rec["locked_until"] - now)
        # 窗口过期，重置
        if now - rec["first_at"] > _LOGIN_WINDOW:
            _login_attempts.pop(ip, None)
            return True, 0
        # 窗口内但未超限
        if rec["count"] < _LOGIN_MAX_ATTEMPTS:
            return True, 0
        # 超限，进入锁定
        rec["locked_until"] = now + _LOGIN_LOCKOUT
        return False, int(_LOGIN_LOCKOUT)

def _login_record_failure(ip: str):
    """记录一次登录失败。"""
    now = time.time()
    with _login_lock:
        rec = _login_attempts.get(ip)
        if rec is None or now - rec["first_at"] > _LOGIN_WINDOW:
            _login_attempts[ip] = {"count": 1, "first_at": now, "locked_until": 0}
        else:
            rec["count"] += 1
        # GC：防止内存无限增长
        if len(_login_attempts) > 5000:
            cutoff = now - _LOGIN_WINDOW * 2
            stale = [k for k, v in _login_attempts.items() if v["first_at"] <= cutoff]
            for k in stale:
                _login_attempts.pop(k, None)

def _login_reset(ip: str):
    """登录成功后清除该 IP 的失败记录。"""
    with _login_lock:
        _login_attempts.pop(ip, None)


# ---- 3. Audit log ----
_audit_initialized = False
_audit_lock = _sec_thr.Lock()

def _init_audit_log():
    global _audit_initialized
    if _audit_initialized:
        return
    try:
        os.makedirs(os.path.dirname(WORKFLOW_DB), exist_ok=True)
        conn = sqlite3.connect(WORKFLOW_DB, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
        conn.commit()
        conn.close()
        _audit_initialized = True
    except Exception as e:
        print(f"[AUDIT] init failed: {e}", flush=True)


def _audit(actor: str, action: str, target: str = "", detail: str = ""):
    """写入审计日志。不抛异常。"""
    if not _audit_initialized:
        _init_audit_log()
    try:
        with _audit_lock:
            conn = sqlite3.connect(WORKFLOW_DB, timeout=10)
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), (actor or "")[:64], (action or "")[:64],
                 (target or "")[:256], (detail or "")[:1024])
            )
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[AUDIT] write failed action={action}: {e}", flush=True)


# ---- 4. LLM input length caps ----
_LLM_TOPIC_MAX = int(os.environ.get("DASHBOARD_LLM_TOPIC_MAX", "500"))
_LLM_CONTEXT_MAX = int(os.environ.get("DASHBOARD_LLM_CONTEXT_MAX", "20000"))
_LLM_TEXT_MAX = int(os.environ.get("DASHBOARD_LLM_TEXT_MAX", "30000"))

def _cap_llm_input(value: str, limit: int) -> str:
    if not value:
        return value
    if len(value) > limit:
        return value[:limit] + "...[truncated]"
    return value


# ---- 5. Sanitized error message for API responses ----
def _safe_err(exc, capture: bool = True) -> str:
    """对外暴露的错误信息：去除文件路径，截短。
    capture=True 时同步上报到 Sentry（如果已配置 DSN）。"""
    if capture:
        _sentry_capture(exc, source="safe_err")
    try:
        msg = str(exc)
    except Exception:
        return "internal error"
    try:
        msg = msg.replace(CE_ROOT, "[...]").replace(os.path.dirname(__file__), "[...]")
    except Exception:
        pass
    return msg[:200] if msg else (exc.__class__.__name__ if hasattr(exc, "__class__") else "error")


# ---- 6. Cookie session login (Stage 2.5, 2026-05-13) ----
import secrets as _sec_secrets

_SESSION_COOKIE = "ai_radar_session"
_SESSION_LIFETIME = int(os.environ.get("DASHBOARD_SESSION_DAYS", "7")) * 86400
_sessions = {}  # token -> {"user": str, "expires_at": float}
_sessions_lock = _sec_thr.Lock()


def _session_create(user: str) -> str:
    token = _sec_secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = {"user": user, "expires_at": time.time() + _SESSION_LIFETIME}
        # GC 过期 / 超量
        if len(_sessions) > 200:
            now = time.time()
            for t in list(_sessions.keys()):
                if _sessions[t]["expires_at"] < now:
                    _sessions.pop(t, None)
    return token


def _session_valid(token: str):
    """返回 user name if valid, else None。"""
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        if s["expires_at"] < time.time():
            _sessions.pop(token, None)
            return None
        return s.get("user")


def _session_revoke(token: str):
    with _sessions_lock:
        _sessions.pop(token, None)


# ---- 6b. CSRF token（绑定到 session，防跨站请求伪造） ----
_csrf_store = {}  # session_token -> csrf_token
_csrf_lock = _sec_thr.Lock()


def _csrf_generate(session_token: str) -> str:
    """为指定 session 生成并存储 CSRF token，返回 csrf token。"""
    csrf_token = _sec_secrets.token_hex(32)
    with _csrf_lock:
        _csrf_store[session_token] = csrf_token
        # 顺带 GC：清理已失效 session 对应的 csrf token
        valid_sessions = set(_sessions.keys())
        for t in list(_csrf_store.keys()):
            if t not in valid_sessions:
                _csrf_store.pop(t, None)
    return csrf_token


def _csrf_validate(session_token: str, csrf_token: str) -> bool:
    """验证 csrf_token 是否与 session_token 匹配。"""
    if not session_token or not csrf_token:
        return False
    with _csrf_lock:
        expected = _csrf_store.get(session_token)
    if not expected:
        return False
    try:
        return _hmac.compare_digest(expected, csrf_token)
    except Exception:
        return False


def _parse_cookies(header_value: str):
    result = {}
    if not header_value:
        return result
    for part in header_value.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2:
            result[kv[0]] = kv[1]
    return result


_topic_scan_timer = None
_skipped_topics = set()
_pending_approvals = {}  # topic -> {topic, write_value, hot_score, added_time}
FEISHU_WEBHOOK_URL = os.environ.get("FEISHU_WEBHOOK_URL", "")

# Persist skipped topics to disk so they survive server restarts
_SKIPPED_TOPICS_FILE = os.path.join(DATA_DIR, ".skipped_topics.json")

def _load_skipped_topics():
    global _skipped_topics
    try:
        if os.path.exists(_SKIPPED_TOPICS_FILE):
            with open(_SKIPPED_TOPICS_FILE) as f:
                _skipped_topics = set(json.load(f))
    except Exception:
        _skipped_topics = set()

def _save_skipped_topics():
    try:
        os.makedirs(os.path.dirname(_SKIPPED_TOPICS_FILE), exist_ok=True)
        with open(_SKIPPED_TOPICS_FILE, "w") as f:
            json.dump(list(_skipped_topics), f, ensure_ascii=False)
    except Exception:
        pass

_load_skipped_topics()

# System health tracking
_system_health = {
    "last_scan_time": 0,
    "last_scan_result": None,  # "success" / "error: ..."
    "last_scan_topics": 0,
    "eval_method": "unknown",  # "llm" / "rule_fallback"
    "last_event_cluster_time": 0,
    "auto_confirmed_total": 0,
    "server_start_time": time.time(),
}

WORKFLOW_DB = os.path.join(CE_ROOT, "content-data", "workflow.db")


def _init_workflow_db():
    os.makedirs(os.path.dirname(WORKFLOW_DB), exist_ok=True)
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        topic TEXT NOT NULL,
        stage TEXT NOT NULL DEFAULT 'analysis',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        analysis_file TEXT,
        article_file TEXT,
        review_file TEXT,
        published_url TEXT,
        analysis_data TEXT,
        article_title TEXT,
        review_score REAL,
        review_verdict TEXT,
        notes TEXT DEFAULT ''
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS project_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        detail TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id)
    )""")
    # News briefs cache table
    conn.execute("""CREATE TABLE IF NOT EXISTS news_briefs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL UNIQUE,
        brief TEXT NOT NULL,
        source_url TEXT DEFAULT '',
        model_used TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    # Page text cache table — stores fetched page content
    conn.execute("""CREATE TABLE IF NOT EXISTS page_texts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        page_text TEXT NOT NULL DEFAULT '',
        fetch_status TEXT NOT NULL DEFAULT 'ok',
        error_detail TEXT DEFAULT '',
        content_length INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()


def _ensure_engagement_table(db_path):
    """Ensure engagement_snapshots table exists in a news DB."""
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS engagement_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        news_item_id INTEGER NOT NULL,
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        shares INTEGER DEFAULT 0,
        snapshot_time TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (news_item_id) REFERENCES news_items(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_engage_news ON engagement_snapshots(news_item_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_engage_time ON engagement_snapshots(snapshot_time)")
    conn.commit()
    conn.close()


def _ensure_topic_events_tables():
    """Create topic_events and related tables in workflow DB."""
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS topic_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_name TEXT NOT NULL,
        event_key TEXT UNIQUE,
        start_date TEXT,
        peak_date TEXT,
        end_date TEXT,
        lifecycle_stage TEXT DEFAULT 'emerging',
        total_articles INTEGER DEFAULT 0,
        total_views INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS event_articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        article_title TEXT NOT NULL,
        source TEXT,
        data_date TEXT,
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        is_ours INTEGER DEFAULT 0,
        url TEXT,
        FOREIGN KEY (event_id) REFERENCES topic_events(id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS our_topic_hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        our_article_id INTEGER,
        our_views INTEGER DEFAULT 0,
        total_event_views INTEGER DEFAULT 0,
        share_pct REAL DEFAULT 0,
        verdict TEXT DEFAULT 'unknown',
        week_start TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES topic_events(id)
    )""")
    conn.commit()
    conn.close()


def _workflow_conn():
    # Stage 2: 30s busy timeout + WAL for concurrent reads/writes
    conn = sqlite3.connect(WORKFLOW_DB, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return conn


def _create_project(topic: str, analysis_file: str = "") -> int:
    now = datetime.now().isoformat()
    conn = _workflow_conn()
    cur = conn.execute(
        "INSERT INTO projects (topic, stage, created_at, updated_at, analysis_file) VALUES (?, 'analysis', ?, ?, ?)",
        (topic, now, now, analysis_file),
    )
    pid = cur.lastrowid
    conn.execute(
        "INSERT INTO project_events (project_id, event_type, detail, created_at) VALUES (?, 'created', ?, ?)",
        (pid, f"选题确认: {topic}", now),
    )
    conn.commit()
    conn.close()
    return pid


def _update_project(pid: int, **kwargs):
    if not kwargs:
        return
    kwargs["updated_at"] = datetime.now().isoformat()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [pid]
    conn = _workflow_conn()
    conn.execute(f"UPDATE projects SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()
    # 使 list_analyses 缓存失效，确保下次请求拿到最新 stage
    _analyses_cache.clear()


def _add_project_event(pid: int, event_type: str, detail: str = ""):
    conn = _workflow_conn()
    conn.execute(
        "INSERT INTO project_events (project_id, event_type, detail, created_at) VALUES (?, ?, ?, ?)",
        (pid, event_type, detail, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def _count_project_events(pid: int, event_type: str) -> int:
    conn = _workflow_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM project_events WHERE project_id = ? AND event_type = ?",
        (pid, event_type),
    ).fetchone()[0]
    conn.close()
    return count


def _list_projects(stage: str = "", limit: int = 50):
    conn = _workflow_conn()
    conn.row_factory = sqlite3.Row
    if stage:
        rows = conn.execute(
            "SELECT * FROM projects WHERE stage = ? ORDER BY updated_at DESC LIMIT ?", (stage, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM projects ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _get_project(pid: int):
    conn = _workflow_conn()
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
    events = conn.execute(
        "SELECT * FROM project_events WHERE project_id = ? ORDER BY created_at", (pid,)
    ).fetchall()
    conn.close()
    if not row:
        return None
    result = dict(row)
    result["events"] = [dict(e) for e in events]
    return result


_init_workflow_db()
_ensure_topic_events_tables()


def get_today():
    return datetime.now().strftime("%Y-%m-%d")


def get_db_path(kind, date=None):
    date = date or get_today()
    path = os.path.join(DATA_DIR, kind, f"{date}.db")
    if not os.path.exists(path) and date == get_today():
        kind_dir = os.path.join(DATA_DIR, kind)
        if os.path.isdir(kind_dir):
            dbs = sorted(glob.glob(os.path.join(kind_dir, "*.db")), reverse=True)
            if dbs:
                path = dbs[0]
    return path


def query_db(db_path, sql, params=()):
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_news(date=None):
    db = get_db_path("news", date)
    return query_db(db, """
        SELECT n.id, n.title, n.platform_id, n.rank, n.url, n.mobile_url,
               n.first_crawl_time, n.last_crawl_time, n.crawl_count,
               p.name as platform_name
        FROM news_items n
        JOIN platforms p ON n.platform_id = p.id
        ORDER BY n.last_crawl_time DESC, n.rank ASC
    """)


def get_rss(date=None):
    db = get_db_path("rss", date)
    return query_db(db, """
        SELECT r.id, r.title, r.feed_id, r.url, r.published_at,
               r.summary, r.author, r.first_crawl_time,
               f.name as feed_name
        FROM rss_items r
        JOIN rss_feeds f ON r.feed_id = f.id
        ORDER BY r.published_at DESC, r.first_crawl_time DESC
    """)


def get_ai_tags(date=None):
    db = get_db_path("news", date)
    return query_db(db, """
        SELECT id, tag, description, priority
        FROM ai_filter_tags
        WHERE status = 'active'
        ORDER BY priority ASC
    """)


def get_ai_results(date=None):
    db = get_db_path("news", date)
    return query_db(db, """
        SELECT r.news_item_id, r.source_type, r.relevance_score,
               t.tag, t.priority
        FROM ai_filter_results r
        JOIN ai_filter_tags t ON r.tag_id = t.id
        WHERE r.status = 'active' AND t.status = 'active'
        ORDER BY r.relevance_score DESC
    """)


def get_stats(date=None):
    news = get_news(date)
    rss = get_rss(date)
    platforms = {}
    for n in news:
        pid = n["platform_name"]
        platforms[pid] = platforms.get(pid, 0) + 1
    feeds = {}
    for r in rss:
        fid = r["feed_name"]
        feeds[fid] = feeds.get(fid, 0) + 1
    actual_db = get_db_path("news", date)
    actual_date = os.path.basename(actual_db).replace(".db", "") if os.path.exists(actual_db) else (date or get_today())
    return {
        "date": actual_date,
        "news_total": len(news),
        "rss_total": len(rss),
        "platforms": platforms,
        "feeds": feeds,
    }


def get_available_dates():
    news_dir = os.path.join(DATA_DIR, "news")
    if not os.path.isdir(news_dir):
        return []
    dbs = glob.glob(os.path.join(news_dir, "*.db"))
    dates = sorted([os.path.basename(f).replace(".db", "") for f in dbs], reverse=True)
    return dates


_TECH_KEYWORDS = {
    # AI / LLM
    "ai", "人工智能", "大模型", "llm", "gpt", "claude", "gemini", "deepseek",
    "openai", "anthropic", "cursor", "copilot", "codex", "agent", "智能体",
    "机器人", "算法", "模型", "训练", "推理", "token", "api",
    "agentic", "mcp", "function calling", "sora", "可灵", "视频生成",
    "图片生成", "aigc", "chatbot", "qwen", "llama", "通义", "文心",
    "kimi", "moonshot", "智谱", "rag", "向量", "embedding", "微调",
    "fine-tune", "prompt", "机器学习", "深度学习", "nlp", "自然语言",
    "机器视觉", "计算机视觉", "语音识别", "语音合成",
    # 硬件 / 算力
    "芯片", "gpu", "nvidia", "英伟达", "算力", "tpu", "asic",
    "服务器", "数据中心", "idc", "光模块", "中际旭创", "光迅",
    # 科技公司 / 人物
    "google", "meta", "微软", "microsoft", "apple", "苹果",
    "字节", "阿里", "百度", "腾讯", "华为", "小米",
    "spacex", "tesla", "特斯拉", "三星", "samsung", "亚马逊", "amazon",
    "sam altman", "黄仁勋", "马斯克", "musk", "扎克伯格",
    "余承东", "雷军", "李彦宏", "马化腾", "张一鸣",
    "奥特曼", "纳德拉", "pichai", "altman",
    # 编程 / 开发
    "编程", "代码", "开发者", "developer", "程序员", "码农",
    "开源", "github", "huggingface", "transformer",
    "python", "javascript", "rust", "golang",
    # 商业 / 投资
    "融资", "估值", "创业", "ipo", "上市", "风投", "vc",
    "科技", "互联网", "云计算", "saas",
    # 自动化 / 机器人
    "自动驾驶", "自动化", "机器人", "无人机", "drone",
    # 新兴技术
    "虚拟现实", "vr", "ar", "元宇宙", "区块链", "web3",
    "量子计算", "量子",
    # 数据
    "数据", "大数据", "数据采集", "爬虫",
    "量化", "部署",
    # 通用科技词
    "tech", "软件", "hardware", "数字化", "智能",
    "半导体", "semiconductor", "制造", "制程", "晶圆",
}


_WEAK_KEYWORDS = {"数据", "上市", "智能", "制造", "部署", "融资", "估值", "创业"}


def _has_tech_signal(title: str) -> bool:
    """Check if title contains at least one tech/AI keyword.

    Weak keywords (generic words like '数据', '上市') only count when
    paired with at least one strong keyword.
    """
    t = title.lower()
    strong_hit = False
    weak_hit = False
    for kw in _TECH_KEYWORDS:
        if kw in t:
            if kw in _WEAK_KEYWORDS:
                weak_hit = True
            else:
                strong_hit = True
    return strong_hit or (weak_hit and strong_hit)


def _get_recent_dates(days=3):
    """Return list of date strings for the most recent N days that have data."""
    kind_dir = os.path.join(DATA_DIR, "news")
    if not os.path.isdir(kind_dir):
        return []
    dbs = sorted(glob.glob(os.path.join(kind_dir, "*.db")), reverse=True)
    dates = []
    for db_path in dbs:
        date_str = os.path.basename(db_path).replace(".db", "")
        dates.append(date_str)
        if len(dates) >= days:
            break
    return dates


def get_ai_filtered(date=None):
    """Return news items that passed AI filter, merged from recent days.

    If date is specified, only return that day's data.
    If date is None, merge the most recent 3 days to ensure continuity.
    """
    if date:
        items = _get_ai_filtered_single(date)
        # Attach cached briefs for single-date queries too
        titles = [item.get("title", "") for item in items if item.get("title")]
        briefs = _get_cached_briefs(titles)
        for item in items:
            t = item.get("title", "")
            if t in briefs:
                item["brief"] = briefs[t]
        # Attach cached page texts
        urls = [it.get("url") or it.get("mobile_url") or "" for it in items]
        urls = [u for u in urls if u and u != "#"]
        pt = _get_cached_page_texts(urls)
        for it in items:
            u = it.get("url") or it.get("mobile_url") or ""
            if u in pt:
                it["page_text"] = pt[u]["text"]
                it["page_text_status"] = pt[u]["status"]
        return items

    recent_dates = _get_recent_dates(3)
    if not recent_dates:
        return []

    all_items = []
    seen_titles = set()
    for d in recent_dates:
        items = _get_ai_filtered_single(d)
        for item in items:
            title = item.get("title", "")
            if title not in seen_titles:
                seen_titles.add(title)
                item["data_date"] = d
                all_items.append(item)

    # 先按日期降序（最新的在前），再按分数降序
    all_items.sort(key=lambda x: (x.get("data_date", ""), x.get("ai_score", 0)), reverse=True)

    # Attach cached briefs
    titles = [item.get("title", "") for item in all_items if item.get("title")]
    briefs = _get_cached_briefs(titles)
    for item in all_items:
        t = item.get("title", "")
        if t in briefs:
            item["brief"] = briefs[t]

    # Attach cached page texts
    urls = [item.get("url") or item.get("mobile_url") or "" for item in all_items]
    urls = [u for u in urls if u and u != "#"]
    page_texts = _get_cached_page_texts(urls)
    for item in all_items:
        u = item.get("url") or item.get("mobile_url") or ""
        if u in page_texts:
            item["page_text"] = page_texts[u]["text"]
            item["page_text_status"] = page_texts[u]["status"]

    return all_items


def _get_ai_filtered_single(date):
    """Return AI filtered items for a single date."""
    news = get_news(date)
    ai_results = get_ai_results(date)
    tagged_ids = {}
    for r in ai_results:
        nid = r["news_item_id"]
        if nid not in tagged_ids:
            tagged_ids[nid] = {"score": r["relevance_score"], "tags": []}
        tagged_ids[nid]["tags"].append(r["tag"])
        tagged_ids[nid]["score"] = max(tagged_ids[nid]["score"], r["relevance_score"])
    filtered = []
    for n in news:
        if n["id"] in tagged_ids:
            if not _has_tech_signal(n.get("title", "")):
                continue
            n["ai_score"] = tagged_ids[n["id"]]["score"]
            n["ai_tags"] = tagged_ids[n["id"]]["tags"]
            filtered.append(n)
    filtered.sort(key=lambda x: x["ai_score"], reverse=True)
    return filtered


# ---- News Brief Generation ----

def _get_cached_briefs(titles: list) -> dict:
    """Fetch cached briefs for a list of titles. Returns {title: brief}."""
    if not titles:
        return {}
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.row_factory = sqlite3.Row
    result = {}
    # SQLite has a limit on variables, batch in chunks of 500
    for i in range(0, len(titles), 500):
        chunk = titles[i:i+500]
        placeholders = ",".join(["?"] * len(chunk))
        rows = conn.execute(
            f"SELECT title, brief FROM news_briefs WHERE title IN ({placeholders})",
            chunk
        ).fetchall()
        for r in rows:
            result[r["title"]] = r["brief"]
    conn.close()
    return result


def _save_brief(title: str, brief: str, url: str = "", model: str = ""):
    """Save a generated brief to cache."""
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.execute(
        "INSERT OR REPLACE INTO news_briefs (title, brief, source_url, model_used) VALUES (?, ?, ?, ?)",
        (title, brief, url, model)
    )
    conn.commit()
    conn.close()


# ---- Page Text Cache ----

def _get_cached_page_texts(urls: list) -> dict:
    """Fetch cached page texts for a list of URLs. Returns {url: {"text": str, "status": str}}."""
    if not urls:
        return {}
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.row_factory = sqlite3.Row
    result = {}
    for i in range(0, len(urls), 500):
        chunk = urls[i:i+500]
        placeholders = ",".join(["?"] * len(chunk))
        rows = conn.execute(
            f"SELECT url, page_text, fetch_status FROM page_texts WHERE url IN ({placeholders})",
            chunk
        ).fetchall()
        for r in rows:
            result[r["url"]] = {"text": r["page_text"], "status": r["fetch_status"]}
    conn.close()
    return result


def _save_page_text(url: str, text: str, status: str = "ok", error: str = ""):
    """Save fetched page text to cache."""
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.execute(
        "INSERT OR REPLACE INTO page_texts (url, page_text, fetch_status, error_detail, content_length, updated_at) "
        "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (url, text, status, error, len(text))
    )
    conn.commit()
    conn.close()


def _purge_bad_page_texts():
    """Remove cached page texts that are known boilerplate / anti-scrape junk.
    Called once on startup to clean stale data so it gets re-fetched with improved logic."""
    _JUNK_MARKERS = [
        '知乎，让每一次点击都充满意义',
        'Sina Visitor System',
        '新浪访客系统',
        '百度搜索', '百度一下',
        '网络不给力，请稍后重试',
        'Just a moment',
        'Checking your browser',
        'Access Denied',
        '请输入验证码',
    ]
    try:
        conn = sqlite3.connect(WORKFLOW_DB)
        total_purged = 0
        for marker in _JUNK_MARKERS:
            cur = conn.execute(
                "DELETE FROM page_texts WHERE page_text LIKE ?",
                (f"%{marker}%",)
            )
            total_purged += cur.rowcount
        # Also purge entries that are very short "ok" status (likely garbage)
        cur2 = conn.execute(
            "DELETE FROM page_texts WHERE fetch_status = 'ok' AND content_length < 50"
        )
        total_purged += cur2.rowcount
        # Purge old toutiao.com entries that were marked "empty" (now handled via mobile API)
        cur_tt = conn.execute(
            "DELETE FROM page_texts WHERE url LIKE '%toutiao.com%' AND fetch_status IN ('empty', 'error')"
        )
        if cur_tt.rowcount > 0:
            print(f"[PageText] Purged {cur_tt.rowcount} stale toutiao.com entries (will re-fetch via mobile API)")
        total_purged += cur_tt.rowcount
        # Also purge entries with highly repetitive content (same line repeated)
        rows = conn.execute(
            "SELECT url, page_text FROM page_texts WHERE fetch_status = 'ok' AND content_length > 0"
        ).fetchall()
        for row in rows:
            url_val, text_val = row
            if not text_val:
                continue
            lines = [l.strip() for l in text_val.split('\n') if l.strip()]
            if len(lines) > 3:
                unique = set(lines)
                if len(unique) <= 2:  # Same 1-2 lines repeated many times
                    conn.execute("DELETE FROM page_texts WHERE url = ?", (url_val,))
                    total_purged += 1
        conn.commit()
        conn.close()
        if total_purged > 0:
            print(f"[PageText] Purged {total_purged} bad cached entries on startup")
    except Exception as e:
        print(f"[PageText] Purge error: {e}")

_purge_bad_page_texts()


def _fetch_toutiao_content(url: str) -> dict:
    """Fetch article content from Toutiao via mobile API.

    Handles two URL patterns:
    - /trending/{topic_id}/  → fetch article list via feed API → get top article content
    - /article/{id} or /group/{id}/ → get content directly via mobile API

    Returns {"text": str, "status": str, "error": str}.
    """
    import httpx, re
    _HEADERS = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Referer": "https://www.toutiao.com/",
    }

    def _get_article_text(group_id: str) -> str:
        """Get article text via m.toutiao.com mobile API."""
        try:
            r = httpx.get(f"https://m.toutiao.com/i{group_id}/info/",
                          timeout=10, headers=_HEADERS)
            data = r.json()
            if not data.get("success") or not data.get("data"):
                return ""
            raw_content = data["data"].get("content", "")
            if not raw_content:
                return data["data"].get("abstract", "") or data["data"].get("title", "")
            # Strip HTML tags, keep text
            text = re.sub(r'<[^>]+>', ' ', raw_content)
            text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<')
            text = text.replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'")
            text = re.sub(r'&#\d+;', '', text)
            text = re.sub(r'&\w+;', '', text)
            text = re.sub(r'\s+', ' ', text).strip()
            # Remove common video placeholder text
            text = re.sub(r'视频加载中\.{0,3}\s*', '', text).strip()
            return text
        except Exception:
            return ""

    try:
        url_lower = url.lower()

        # ── Pattern 1: /trending/{topic_id}/ → fetch article list first ──
        trending_match = re.search(r'/trending/(\d+)', url)
        if trending_match:
            topic_id = trending_match.group(1)
            # Try to get articles under this trending topic
            r = httpx.get(f"https://www.toutiao.com/api/pc/feed/?tag=event_{topic_id}",
                          timeout=10, headers=_HEADERS)
            feed_data = r.json()
            articles = feed_data.get("data", [])

            # Also try direct mobile API with topic_id (sometimes works)
            direct_text = _get_article_text(topic_id)

            if articles:
                # Collect text from top articles (prefer non-video, longer content)
                collected = []
                if direct_text and len(direct_text) > 50:
                    collected.append(direct_text)
                for art in articles[:6]:
                    gid = str(art.get("group_id") or art.get("item_id") or "")
                    if not gid:
                        continue
                    text = _get_article_text(gid)
                    if text and len(text) > 30:
                        title = art.get("title", "")
                        source = art.get("source", "")
                        entry = f"【{title}】({source})\n{text}" if title else text
                        collected.append(entry)
                    if len(collected) >= 3:
                        break

                if collected:
                    full_text = "\n\n---\n\n".join(collected)
                    if len(full_text) > 6000:
                        full_text = full_text[:6000]
                    return {"text": full_text, "status": "ok", "error": ""}

            # Fallback: if direct_text worked
            if direct_text and len(direct_text) > 30:
                return {"text": direct_text, "status": "ok", "error": ""}

            return {"text": "", "status": "empty",
                    "error": f"toutiao trending topic {topic_id}: no article content found"}

        # ── Pattern 2: /article/{id} or /group/{id}/ → direct mobile API ──
        art_match = re.search(r'/(?:article|group|a)/(\d+)', url)
        if art_match:
            art_id = art_match.group(1)
            text = _get_article_text(art_id)
            if text and len(text) > 30:
                return {"text": text, "status": "ok", "error": ""}
            return {"text": "", "status": "empty",
                    "error": f"toutiao article {art_id}: no content or too short"}

        # ── Pattern 3: Unknown toutiao URL pattern ──
        return {"text": "", "status": "empty", "error": "toutiao URL pattern not recognized"}

    except httpx.TimeoutException:
        return {"text": "", "status": "timeout", "error": "toutiao API timeout"}
    except Exception as e:
        return {"text": "", "status": "error", "error": f"toutiao fetch error: {str(e)[:200]}"}


def _fetch_page_text_from_url(url: str) -> dict:
    """Fetch and extract text content from a URL. Returns {"text": str, "status": str, "error": str}."""
    import httpx, re
    if _is_private_or_invalid_url(url):
        return {"text": "", "status": "error", "error": "private URL blocked"}

    # ── Toutiao: use dedicated mobile API instead of HTTP scraping ──
    url_lower = url.lower()
    if 'toutiao.com' in url_lower and 'toutiaocdn.com' not in url_lower:
        return _fetch_toutiao_content(url)

    # ── Skip URLs that are known to not have article content ──
    _SKIP_URL_PATTERNS = [
        'baidu.com/s?', 'so.com/s?', 'sogou.com/web?',       # search result pages
        'google.com/search', 'bing.com/search',
        'passport.', 'login.', 'accounts.',                   # login pages
        '/search?', '/s?wd=',                                 # search queries
    ]
    # Sites that require JS rendering — HTTP GET returns no real content
    # Note: toutiao.com is handled separately via _fetch_toutiao_content() above
    _JS_ONLY_DOMAINS = [
        'weibo.com', 'm.weibo.cn',                            # Sina Weibo
        'bilibili.com', 'b23.tv',                             # Bilibili
        'zhihu.com',                                          # Zhihu
        'toutiaocdn.com',                                     # Toutiao CDN (images/assets)
        'douyin.com',                                         # Douyin
        'xiaohongshu.com', 'xhslink.com',                    # Xiaohongshu
        'mp.weixin.qq.com',                                   # WeChat articles (anti-scrape)
    ]
    for pat in _SKIP_URL_PATTERNS:
        if pat in url_lower:
            return {"text": "", "status": "empty", "error": f"skipped: {pat} URL"}
    for domain in _JS_ONLY_DOMAINS:
        if domain in url_lower:
            return {"text": "", "status": "empty", "error": f"JS-only site: {domain}"}

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://www.google.com/",
        }
        r = httpx.get(url, timeout=12, follow_redirects=True, headers=headers)
        final_url = str(r.url)
        if _is_private_or_invalid_url(final_url):
            return {"text": "", "status": "error", "error": "redirect to private address"}
        html = r.text[:2 * 1024 * 1024]

        # ── 1. Try to extract from <article> or known content containers first ──
        article_text = ""
        from html.parser import HTMLParser
        # Try BS4-like extraction with regex for article/main content
        article_match = re.search(
            r'<article[^>]*>(.*?)</article>',
            html, flags=re.DOTALL | re.IGNORECASE
        )
        if not article_match:
            # Try common content selectors
            for pattern in [
                r'<div[^>]*class="[^"]*(?:article[_-]?content|post[_-]?content|entry[_-]?content|rich[_-]?content|content[_-]?body|main[_-]?content|post[_-]?body|text[_-]?content)[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*id="(?:article|content|post|main)[_-]?(?:content|body|text|detail)"[^>]*>(.*?)</div>',
                r'<main[^>]*>(.*?)</main>',
            ]:
                m = re.search(pattern, html, flags=re.DOTALL | re.IGNORECASE)
                if m:
                    article_match = m
                    break

        target_html = article_match.group(1) if article_match else html

        # ── 2. Strip non-content tags ──
        for tag in ['script', 'style', 'nav', 'header', 'footer', 'aside',
                     'noscript', 'svg', 'iframe', 'form', 'button', 'input',
                     'select', 'textarea', 'label']:
            target_html = re.sub(
                r'<' + tag + r'[^>]*>.*?</' + tag + r'>',
                '', target_html, flags=re.DOTALL | re.IGNORECASE
            )
        # Strip self-closing / void tags that may contain noise
        target_html = re.sub(r'<(?:img|br|hr|meta|link|input)[^>]*/?\s*>', '', target_html, flags=re.IGNORECASE)

        # ── 3. Convert HTML to text ──
        # Preserve paragraph boundaries
        target_html = re.sub(r'</(?:p|div|h[1-6]|li|tr|blockquote|section)>', '\n\n', target_html, flags=re.IGNORECASE)
        target_html = re.sub(r'<br\s*/?\s*>', '\n', target_html, flags=re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', target_html)
        # Decode common HTML entities
        text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'")
        text = re.sub(r'&#\d+;', '', text)
        text = re.sub(r'&\w+;', '', text)
        # Clean whitespace
        text = re.sub(r'[ \t]+', ' ', text)
        text = re.sub(r'\n[ \t]+', '\n', text)
        text = re.sub(r'\n{3,}', '\n\n', text)

        # ── 4. Filter lines ──
        lines = [l.strip() for l in text.split('\n') if l.strip()]

        # Known boilerplate/anti-scrape patterns to remove
        _JUNK_PATTERNS = [
            '知乎，让每一次点击都充满意义',
            '欢迎来到知乎，发现问题背后的世界',
            '登录后你可以', '下载知乎客户端',
            'Sina Visitor System', '新浪访客系统',
            '网络不给力，请稍后重试', '请稍后再试',
            '百度搜索', '百度一下', '百度首页',
            '使用百度前必读', '意见反馈',
            '请输入验证码', '滑动验证', '安全验证',
            'Access Denied', 'Forbidden', '403 Forbidden',
            'Just a moment', 'Checking your browser', 'Enable JavaScript',
            'Please enable cookies', 'please wait',
            '微博-随时随地发现新鲜事', '请先登录微博',
            'bilibili.com', '哔哩哔哩',
            '©', 'Copyright', 'All Rights Reserved',
            'cookie', 'Cookie', '隐私政策', '服务协议', '用户协议',
            '关于我们', '联系我们', '意见反馈', '举报',
            '分享到微信', '分享到朋友圈', '分享到QQ',
            '免责声明', '版权所有', '备案号',
        ]
        def is_junk_line(line):
            if len(line) < 6:
                return True
            for jp in _JUNK_PATTERNS:
                if jp in line:
                    return True
            # Pure URL line
            if re.match(r'^https?://', line):
                return True
            # Navigation-style short fragments (e.g. "首页 发现 关注 消息")
            if len(line) < 20 and line.count(' ') >= 3:
                return True
            return False

        content_lines = [l for l in lines if not is_junk_line(l)]

        # ── 5. Deduplicate (preserve order) ──
        seen = set()
        deduped = []
        for l in content_lines:
            # Normalize for dedup comparison
            key = re.sub(r'\s+', '', l)[:80]
            if key not in seen:
                seen.add(key)
                deduped.append(l)
        content_lines = deduped

        # ── 6. Quality check: detect anti-scrape / boilerplate pages ──
        full_text = '\n'.join(content_lines)
        # If total content is too short after cleaning, mark as empty
        if len(full_text) < 30:
            return {"text": "", "status": "empty", "error": "content too short after filtering"}

        # If most lines are very short (nav/menu fragments), likely not article
        if len(content_lines) > 5:
            short_lines = sum(1 for l in content_lines if len(l) < 15)
            if short_lines / len(content_lines) > 0.7:
                return {"text": "", "status": "empty", "error": "mostly short fragments, likely not article content"}

        # ── 7. Truncate to reasonable display length ──
        text = '\n\n'.join(content_lines[:80])
        if len(text) > 6000:
            text = text[:6000]

        return {"text": text, "status": "ok", "error": ""}
    except httpx.TimeoutException:
        return {"text": "", "status": "timeout", "error": "request timeout"}
    except Exception as e:
        return {"text": "", "status": "error", "error": str(e)[:200]}


def _fetch_and_cache_page_text(url: str) -> dict:
    """Fetch page text and save to cache. Returns result dict."""
    result = _fetch_page_text_from_url(url)
    _save_page_text(url, result["text"], result["status"], result.get("error", ""))
    return result


def _generate_brief_llm(title: str, url: str = "") -> dict:
    """Generate a 1-3 sentence brief for a news item using LLM.
    Returns {"brief": str, "model": str} or {"error": str}.
    """
    prompt = (
        "你是一个资深科技新闻编辑。根据以下新闻标题，用1-3句话概括核心事件、关键观点和意义。"
        "要求：简洁有力，突出关键信息，避免空话套话。只输出摘要文本，不要加标点符号开头。\n\n"
        f"标题：{title}"
    )

    # Try models in order: DeepSeek (free/fast) → Gemini Flash → TokenKey Claude
    import httpx

    # 1. Try DeepSeek
    ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if ds_key:
        try:
            resp = httpx.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {ds_key}", "Content-Type": "application/json"},
                json={"model": "deepseek-chat", "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 200, "temperature": 0.3},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                brief = data["choices"][0]["message"]["content"].strip()
                return {"brief": brief, "model": "deepseek"}
        except Exception as e:
            print(f"[Brief] DeepSeek failed: {e}")

    # 2. Try Gemini Flash
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if gemini_key:
        try:
            resp = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}",
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"maxOutputTokens": 200, "temperature": 0.3}},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                brief = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                return {"brief": brief, "model": "gemini-flash"}
        except Exception as e:
            print(f"[Brief] Gemini failed: {e}")

    # 3. Try TokenKey (Claude)
    tk_key = os.environ.get("TOKENKEY_API_KEY", "")
    tk_base = os.environ.get("TOKENKEY_API_BASE", "https://api.tokenkey.dev/v1")
    if tk_key:
        try:
            resp = httpx.post(
                f"{tk_base}/chat/completions",
                headers={"Authorization": f"Bearer {tk_key}", "Content-Type": "application/json"},
                json={"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 200, "temperature": 0.3},
                timeout=20,
            )
            if resp.status_code == 200:
                data = resp.json()
                brief = data["choices"][0]["message"]["content"].strip()
                return {"brief": brief, "model": "claude-sonnet"}
        except Exception as e:
            print(f"[Brief] TokenKey failed: {e}")

    return {"error": "所有模型均不可用"}


def _generate_and_cache_brief(title: str, url: str = "") -> dict:
    """Generate brief and save to cache. Returns {"brief": str, "model": str} or {"error": str}."""
    result = _generate_brief_llm(title, url)
    if "brief" in result:
        _save_brief(title, result["brief"], url, result.get("model", ""))
    return result


def _send_feishu_notification(title: str, content: str):
    """Send a notification via Feishu group webhook."""
    url = FEISHU_WEBHOOK_URL
    if not url:
        return
    import urllib.request
    payload = json.dumps({
        "msg_type": "interactive",
        "card": {
            "header": {"title": {"tag": "plain_text", "content": title}, "template": "green"},
            "elements": [{"tag": "markdown", "content": content}],
        },
    }).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        print(f"[Feishu] Notification sent: {title}")
    except Exception as e:
        print(f"[Feishu] Failed: {e}")


def _launch_analysis_job(topic: str, context: str = "") -> str:
    """Shared function to launch a multi-model analysis job with progress tracking."""
    _cleanup_old_jobs()
    job_id = f"analysis_{int(datetime.now().timestamp())}"
    progress = {}
    project_id = _create_project(topic)
    _running_jobs[job_id] = {
        "status": "running",
        "type": "analysis",
        "topic": topic,
        "progress": progress,
        "start_time": datetime.now().isoformat(),
        "project_id": project_id,
    }

    def run():
        try:
            from article.multi_model import analyze_topic, save_analysis
            result = analyze_topic(topic, context, progress_store=progress)
            filepath = save_analysis(result)
            rd = result.to_dict()
            _running_jobs[job_id] = {
                "status": "done",
                "type": "analysis",
                "topic": topic,
                "result": rd,
                "file": filepath,
                "progress": progress,
                "project_id": project_id,
            }
            _update_project(project_id, stage="insights", analysis_file=filepath)
            _add_project_event(project_id, "analysis_done",
                               f"分析完成: {rd.get('total_insights', 0)} 个洞察")
            model_total = rd.get('models_succeeded', 0) + rd.get('models_failed', 0)
            _send_feishu_notification(
                f"✅ 分析完成: {topic}",
                f"**话题**: {topic}\n"
                f"**成功模型**: {rd.get('models_succeeded', 0)}/{model_total}\n"
                f"**总洞察数**: {rd.get('total_insights', 0)}\n"
                f"**共识观点**: {len(rd.get('consensus_points', []))} 个\n"
                f"**分歧观点**: {len(rd.get('disagreement_points', []))} 个\n\n"
                f"🔗 [查看详情]({os.environ.get('DASHBOARD_URL', 'https://content.orbitlogic.dev')})",
            )
            # 分析完成后默认停在「选观点」阶段，等用户手动勾选观点再写作（人工把控质量）。
            # 之前是 AI 自动选 7 个观点抢先写，跳过了用户的选择步骤。
            # 如需恢复全自动 pipeline：设环境变量 AUTO_WRITE_ENABLED=1
            if os.environ.get("AUTO_WRITE_ENABLED", "0") == "1" and rd.get('total_insights', 0) >= 5:
                _auto_generate_article(filepath, project_id, topic)
        except Exception as e:
            _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic, "project_id": project_id}
            _update_project(project_id, stage="failed")
            _add_project_event(project_id, "analysis_failed", str(e)[:500])
            _send_feishu_notification(
                f"❌ 分析失败: {topic}",
                f"**话题**: {topic}\n**错误**: {str(e)[:200]}",
            )

    threading.Thread(target=run, daemon=True).start()
    return job_id


def _auto_generate_article(analysis_file: str, project_id: int, topic: str):
    """Auto-generate article after analysis completes (full-auto pipeline)."""
    job_id = f"article_auto_{int(time.time())}"
    _running_jobs[job_id] = {"status": "running", "type": "article", "topic": topic, "project_id": project_id}

    def run():
        try:
            from article.generator import generate_article, save_article
            import json as _json

            with open(analysis_file, "r") as f:
                analysis = _json.load(f)

            # Auto-select top insights (high/medium originality, max 7)
            insights = analysis.get("merged_insights", [])
            selected = []
            for i, ins in enumerate(insights):
                orig = ins.get("originality", "low")
                if orig in ("high", "medium") or ins.get("source_label") == "Inspire":
                    selected.append(i)
                if len(selected) >= 7:
                    break
            # If less than 3, add top-ranked ones
            if len(selected) < 3:
                for i in range(min(5, len(insights))):
                    if i not in selected:
                        selected.append(i)
                    if len(selected) >= 5:
                        break

            result = generate_article(analysis, selected_indexes=selected or None)

            # 生成配图并嵌入文章
            updated_content, img_results = _generate_and_embed_images(result["content"])
            result["content"] = updated_content
            if img_results:
                result["images"] = [i for i in img_results if "filename" in i]

            article_path = save_article(result)  # Uses default output dir

            _running_jobs[job_id] = {
                "status": "done", "type": "article", "topic": topic,
                "result": result, "file": article_path, "project_id": project_id,
            }
            _update_project(project_id, stage="writing", article_file=article_path,
                            article_title=result.get("title", ""))
            _add_project_event(project_id, "article_auto_generated",
                               f"自��生成文章: {result.get('title','')} ({result.get('word_count',0)}字)")

            # 不再自动启动审核 — 留给用户手动点击"发起机审"按钮
            # _auto_review_article(article_path, project_id, topic)

        except Exception as e:
            _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic}
            _update_project(project_id, stage="failed")
            _add_project_event(project_id, "article_gen_failed", f"自动写文章失败: {str(e)[:200]}")
            print(f"[Auto-Article] Error for {topic[:30]}: {e}")

    threading.Thread(target=run, daemon=True).start()
    print(f"[Auto-Article] Started for: {topic[:40]} (project {project_id})")


def _auto_review_article(article_file: str, project_id: int, topic: str):
    """Auto-review article after generation (full-auto pipeline)."""
    job_id = f"review_auto_{int(time.time())}"
    _running_jobs[job_id] = {"status": "running", "type": "review", "topic": topic, "project_id": project_id}

    def run():
        try:
            from article.reviewer import review_article, save_review

            with open(article_file, "r", encoding="utf-8") as f:
                article_content = f.read()
            article_title = os.path.basename(article_file).rsplit(".", 1)[0]
            review = review_article(article_content, article_title=article_title)
            review_path = save_review(review, article_file)

            score = review.get("overall_score", 0) if isinstance(review, dict) else 0
            verdict = review.get("verdict", "unknown") if isinstance(review, dict) else "unknown"

            _running_jobs[job_id] = {
                "status": "done", "type": "review", "topic": topic,
                "result": review, "file": review_path, "project_id": project_id,
            }

            _update_project(project_id, stage="review",
                            review_file=review_path, review_score=score, review_verdict=verdict)
            _add_project_event(project_id, "auto_review_done",
                               f"AI审核完成: {score}分/{verdict}")

            # 高分自动推进，低分自动修订，中间留给人审
            # 阈值 9.0: 只有真正高分才跳过人审，8.x 都进人审让用户把关
            revise_count = _count_project_events(project_id, "auto_revision_done")
            if verdict == "publish" and score >= 9.0:
                _update_project(project_id, stage="ready")
                _add_project_event(project_id, "auto_approved",
                                   f"高分自动通过: {score}分/{verdict} → 待发布")
                _send_feishu_notification(
                    f"✅ 自动通过: {topic[:30]}",
                    f"**评分**: {score}/10 · **判定**: {verdict}\n**阶段**: 已自动进入待发布",
                )
            elif verdict == "revise" and revise_count < 2:
                _add_project_event(project_id, "auto_revise_triggered",
                                   f"自动修订 (第{revise_count+1}轮): {score}分/{verdict}")
                _auto_revise_article(article_file, review_path, project_id, topic)
                _send_feishu_notification(
                    f"🔄 自动修订: {topic[:30]}",
                    f"**评分**: {score}/10 · **判定**: {verdict}\n**阶段**: 自动修订第{revise_count+1}轮",
                )
            else:
                _update_project(project_id, stage="human_review")
                _send_feishu_notification(
                    f"👤 需人审: {topic[:30]}",
                    f"**评分**: {score}/10 · **判定**: {verdict}\n**阶段**: 需人工审核决策",
                )
        except Exception as e:
            _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic}
            # 即使审核失败，文章已生成，标记为 human_review
            _update_project(project_id, stage="human_review")
            _add_project_event(project_id, "auto_review_failed", f"自动审核失败: {str(e)[:200]}")
            print(f"[Auto-Review] Error for {topic[:30]}: {e}")

    threading.Thread(target=run, daemon=True).start()


def _auto_revise_article(article_file: str, review_file: str, project_id: int, topic: str):
    """Auto-revise article when review verdict is 'revise' (full-auto pipeline)."""
    job_id = f"revise_auto_{int(time.time())}"
    _running_jobs[job_id] = {"status": "running", "type": "revision", "topic": topic, "project_id": project_id}

    def run():
        try:
            from article.generator import revise_article, save_revised_article

            with open(article_file, "r", encoding="utf-8") as f:
                content = f.read()
            with open(review_file, "r", encoding="utf-8") as f:
                review = json.load(f)

            title = ""
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    for line in parts[1].split("\n"):
                        if line.startswith("title:"):
                            title = line.split(":", 1)[1].strip()

            result = revise_article(
                article_content=content,
                review=review,
                article_title=title,
            )
            revised_path = save_revised_article(result, article_file)

            _running_jobs[job_id] = {
                "status": "done", "type": "revision", "topic": topic,
                "result": {k: v for k, v in result.items() if k != "content"},
                "file": revised_path, "project_id": project_id,
            }

            # Update project with revised article, then re-review
            _update_project(project_id, stage="review", article_file=revised_path)
            _add_project_event(project_id, "auto_revision_done",
                               f"自动修订: {result.get('title', '')} "
                               f"({result.get('word_count', 0)}字)")

            # Re-review the revised article
            _auto_review_article(revised_path, project_id, topic)

        except Exception as e:
            _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic}
            _add_project_event(project_id, "auto_revision_failed", f"自动修订失败: {str(e)[:200]}")
            print(f"[Auto-Revise] Error for {topic[:30]}: {e}")

    threading.Thread(target=run, daemon=True).start()
    print(f"[Auto-Revise] Started for: {topic[:40]} (project {project_id})")


def _list_video_scripts():
    try:
        from article.video_workbench import list_scripts
        return list_scripts()
    except Exception as e:
        return {"error": str(e)}


def _get_engagement(date=None, item_id=None):
    """读取某日某条新闻的互动/热度数据时间序列。

    优先使用 engagement_snapshots 表；若为空则 fallback 到 rank_history
    （将排名反转为热度分数：rank 1 = 100分, rank 50 = 2分）。
    """
    db = get_db_path("news", date)
    if not os.path.exists(db):
        return []
    _ensure_engagement_table(db)

    if item_id:
        try:
            iid = int(item_id)
        except (TypeError, ValueError):
            return []
        # 先查 engagement_snapshots
        rows = query_db(db, """
            SELECT id, news_item_id, views, likes, comments, shares, snapshot_time
            FROM engagement_snapshots
            WHERE news_item_id = ?
            ORDER BY snapshot_time ASC
        """, (iid,))
        if rows:
            return rows
        # Fallback: 用 rank_history 生成热度时间序列
        return query_db(db, """
            SELECT r.id, r.news_item_id,
                   MAX(1, 101 - r.rank) as views,
                   0 as likes, 0 as comments, 0 as shares,
                   r.crawl_time as snapshot_time
            FROM rank_history r
            WHERE r.news_item_id = ?
            ORDER BY r.crawl_time ASC
        """, (iid,))

    # 不指定 item_id：返回当日所有新闻的最新热度
    rows = query_db(db, """
        SELECT e.news_item_id, e.views, e.likes, e.comments, e.shares, e.snapshot_time,
               n.title, n.platform_id
        FROM engagement_snapshots e
        JOIN news_items n ON n.id = e.news_item_id
        WHERE e.id IN (
            SELECT MAX(id) FROM engagement_snapshots GROUP BY news_item_id
        )
        ORDER BY e.views DESC
    """)
    if rows:
        return rows
    # Fallback: 用 rank_history 最新一次排名作为热度
    return query_db(db, """
        SELECT r.news_item_id,
               MAX(1, 101 - r.rank) as views,
               0 as likes, 0 as comments, 0 as shares,
               r.crawl_time as snapshot_time,
               n.title, n.platform_id
        FROM rank_history r
        JOIN news_items n ON n.id = r.news_item_id
        WHERE r.id IN (
            SELECT MAX(id) FROM rank_history GROUP BY news_item_id
        )
        ORDER BY views DESC
        LIMIT 50
    """)


def _get_topic_events(limit=50):
    """读取所有热点事件，按总阅读量降序。"""
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT id, event_name, event_key, start_date, peak_date, end_date,
                   lifecycle_stage, total_articles, total_views, created_at, updated_at
            FROM topic_events
            ORDER BY total_views DESC, updated_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _get_topic_hits(week_start=None):
    """读取本周或指定周的"我们抓住热点"分析结果。"""
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.row_factory = sqlite3.Row
    try:
        if week_start:
            rows = conn.execute("""
                SELECT h.id, h.event_id, h.our_article_id, h.our_views,
                       h.total_event_views, h.share_pct, h.verdict, h.week_start,
                       e.event_name, e.lifecycle_stage
                FROM our_topic_hits h
                LEFT JOIN topic_events e ON e.id = h.event_id
                WHERE h.week_start = ?
                ORDER BY h.share_pct DESC
            """, (week_start,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT h.id, h.event_id, h.our_article_id, h.our_views,
                       h.total_event_views, h.share_pct, h.verdict, h.week_start,
                       e.event_name, e.lifecycle_stage
                FROM our_topic_hits h
                LEFT JOIN topic_events e ON e.id = h.event_id
                ORDER BY h.created_at DESC
                LIMIT 50
            """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _get_topic_trends(top_n=10):
    """返回 Top N 事件的每日文章数分布，用于热度趋势图。"""
    conn = sqlite3.connect(WORKFLOW_DB)
    conn.row_factory = sqlite3.Row
    try:
        # 按文章数排名取 Top N 事件
        events = conn.execute("""
            SELECT id, event_name, event_key, lifecycle_stage, total_articles,
                   start_date, updated_at
            FROM topic_events
            ORDER BY total_articles DESC, updated_at DESC
            LIMIT ?
        """, (top_n,)).fetchall()

        result = []
        for ev in events:
            # 获取该事件每天的文章数
            daily = conn.execute("""
                SELECT data_date, COUNT(*) as count, GROUP_CONCAT(source, '|') as sources
                FROM event_articles
                WHERE event_id = ?
                GROUP BY data_date
                ORDER BY data_date
            """, (ev["id"],)).fetchall()

            result.append({
                "event_name": ev["event_name"],
                "lifecycle_stage": ev["lifecycle_stage"],
                "total_articles": ev["total_articles"],
                "start_date": ev["start_date"],
                "daily_trend": [
                    {"date": d["data_date"], "count": d["count"],
                     "sources": list(set(d["sources"].split("|"))) if d["sources"] else []}
                    for d in daily
                ],
            })
        return result
    finally:
        conn.close()


def _get_recommendations():
    try:
        from article.topic_detector import get_cached_recommendations
        data = get_cached_recommendations()
        recs = data.get("recommendations", [])
        filtered = [r for r in recs if r.get("topic_title", "") not in _skipped_topics]
        # 标注待审批状态
        for r in filtered:
            t = r.get("topic_title", "")
            if t in _pending_approvals:
                r["pending_approval"] = True
                r["pending_since"] = _pending_approvals[t].get("added_time", "")
        data["recommendations"] = filtered
        data["count"] = len(filtered)
        data["pending_count"] = len(_pending_approvals)
        return data
    except Exception as e:
        return {"recommendations": [], "scan_time": 0, "count": 0, "error": str(e)}


def _analytics_summary():
    try:
        from article.analytics import get_analytics_summary
        return get_analytics_summary()
    except Exception as e:
        return {"error": str(e)}


def _analytics_articles():
    try:
        from article.analytics import get_all_articles
        return get_all_articles()
    except Exception as e:
        return {"error": str(e)}


def _analytics_competitors():
    try:
        from article.analytics import get_competitors
        return get_competitors()
    except Exception as e:
        return {"error": str(e)}


def _competitors_timeline(params):
    try:
        from article.analytics import get_competitor_timeline
        days = int(params.get("days", ["14"])[0])
        return get_competitor_timeline(days=days)
    except Exception as e:
        return {"error": str(e)}


def _competitors_topic_stats(params):
    try:
        from article.analytics import get_competitor_topic_stats
        days = int(params.get("days", ["30"])[0])
        return get_competitor_topic_stats(days=days)
    except Exception as e:
        return {"error": str(e)}


def _competitors_cadence(params):
    try:
        from article.analytics import get_publishing_cadence
        days = int(params.get("days", ["30"])[0])
        return get_publishing_cadence(days=days)
    except Exception as e:
        return {"error": str(e)}


def _competitors_coverage():
    try:
        from article.analytics import get_coverage_comparison
        return get_coverage_comparison()
    except Exception as e:
        return {"error": str(e)}


def _competitors_insights():
    try:
        from article.analytics import get_latest_insights
        return get_latest_insights()
    except Exception as e:
        return {"error": str(e)}


def _competitors_scan_status():
    try:
        from article.analytics import get_scan_status
        return get_scan_status()
    except Exception as e:
        return {"error": str(e)}


def _get_templates():
    try:
        from article.formatter import get_templates
        return get_templates()
    except Exception:
        return [
            {"id": "analysis", "name": "深度分析", "description": "适合深度行业分析", "accent": "#2563eb"},
            {"id": "opinion", "name": "观点评论", "description": "有态度的短评", "accent": "#7c3aed"},
            {"id": "report", "name": "实录纪实", "description": "事件记录/报告", "accent": "#059669"},
            {"id": "flash", "name": "快讯速递", "description": "短消息/快讯合集", "accent": "#d97706"},
        ]


_analyses_cache: dict = {}  # {"result": [...], "ts": float}
_ANALYSES_CACHE_TTL = 3  # seconds – avoid repeated reads during rapid UI reloads


def list_analyses():
    """List saved analysis files, enriched with workflow stage.

    Performance: single batch DB query + dict lookup (was N queries).
    Results are cached for 3 s to handle rapid UI reloads.
    """
    now = time.time()
    cached = _analyses_cache
    if cached.get("result") is not None and now - cached.get("ts", 0) < _ANALYSES_CACHE_TTL:
        return cached["result"]

    if not os.path.isdir(ANALYSIS_STORE):
        return []
    files = glob.glob(os.path.join(ANALYSIS_STORE, "*.json"))
    # 过滤掉非 analysis 的辅助文件
    files = [
        f for f in files
        if not os.path.basename(f).startswith(("source_verification_", "article_picks", "today_suggestions"))
        and not f.endswith(".verification.json")
    ]

    # ── 一次性加载所有 project 行，构建路径 → project 字典 ──
    conn = _workflow_conn()
    conn.row_factory = sqlite3.Row
    all_projs = conn.execute(
        "SELECT id, stage, analysis_file, topic, created_at FROM projects").fetchall()
    conn.close()

    path_lookup: dict = {}      # exact analysis_file → row
    realpath_lookup: dict = {}   # realpath(analysis_file) → row
    basename_lookup: dict = {}   # basename → row (fallback for different mount paths)
    for p in all_projs:
        af = p["analysis_file"]
        if af:
            path_lookup[af] = p
            basename_lookup[os.path.basename(af)] = p
            try:
                realpath_lookup[os.path.realpath(af)] = p
            except Exception:
                pass

    results = []
    seen_files = set()  # 跟踪已处理的文件 basename，用于后续 DB 补漏
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # 必须有 model_results 才算真正的 analysis
            if not data.get("model_results"):
                continue
            total = data.get("total_insights", 0) or 0
            succeeded = data.get("models_succeeded", 0) or 0
            topic = data.get("topic", "")

            # 匹配 project：先精确路径，再 realpath，再 basename（容器内不同挂载点）
            proj = path_lookup.get(f)
            if not proj:
                proj = realpath_lookup.get(os.path.realpath(f))
            if not proj:
                proj = basename_lookup.get(os.path.basename(f))

            stage = "insights" if total > 0 else ("failed" if succeeded == 0 else "analysis")
            project_id = None
            if proj:
                stage = proj["stage"]
                project_id = proj["id"]
            results.append({
                "file": f,
                "topic": topic,
                "total_insights": total,
                "models_succeeded": succeeded,
                "timestamp": data.get("timestamp", 0),
                "stage": stage,
                "project_id": project_id,
            })
            seen_files.add(os.path.basename(f))
        except Exception:
            pass

    # ── DB 补漏：确保所有有 analysis_file 的项目都出现 ──
    # 处理文件路径不在当前扫描目录（路径不匹配/已移动）的情况
    for p in all_projs:
        af = p["analysis_file"]
        if not af:
            continue
        bn = os.path.basename(af)
        if bn in seen_files:
            continue  # 已通过文件扫描加入
        # 尝试在 ANALYSIS_STORE 下查找
        candidate = os.path.join(ANALYSIS_STORE, bn)
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not data.get("model_results"):
                continue
            results.append({
                "file": candidate,
                "topic": data.get("topic", ""),
                "total_insights": data.get("total_insights", 0) or 0,
                "models_succeeded": data.get("models_succeeded", 0) or 0,
                "timestamp": data.get("timestamp", 0),
                "stage": p["stage"],
                "project_id": p["id"],
            })
            seen_files.add(bn)
        except Exception:
            pass

    # ── 补充无 analysis 文件的进行中/中断 project ──
    # 分析中（stage=analysis）还没生成文件，重启后内存 job 丢失会"消失"；
    # 这里从 db 直接补，确保刷新/切页/重启后生产线仍能看到（分析中 or 失败可重试）。
    existing_pids = {r.get("project_id") for r in results if r.get("project_id")}
    for p in all_projs:
        if p["id"] in existing_pids:
            continue
        if p["stage"] not in ("analysis", "failed"):
            continue  # 其他阶段应有文件，已由上面文件扫描处理
        if p["analysis_file"]:
            continue  # 有文件的不在此补
        ts = 0
        try:
            ts = datetime.fromisoformat(p["created_at"]).timestamp()
        except Exception:
            pass
        results.append({
            "file": None,
            "topic": p["topic"],
            "total_insights": 0,
            "models_succeeded": 0,
            "timestamp": ts,
            "stage": p["stage"],
            "project_id": p["id"],
        })

    _analyses_cache["result"] = results
    _analyses_cache["ts"] = now
    return results


def list_articles():
    """List saved article files."""
    if not os.path.isdir(ARTICLES_STORE):
        return []
    files = glob.glob(os.path.join(ARTICLES_STORE, "*.md"))
    results = []
    for f in sorted(files, key=os.path.getmtime, reverse=True)[:20]:
        meta_path = f.replace(".md", ".meta.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                meta["file"] = f
                results.append(meta)
            except Exception:
                pass
        else:
            results.append({"file": f, "title": os.path.basename(f)})

        review_path = f.replace(".md", ".review.json")
        if os.path.exists(review_path) and results:
            try:
                with open(review_path, "r", encoding="utf-8") as fh:
                    review = json.load(fh)
                results[-1]["review"] = {
                    "overall_score": review.get("overall_score", 0),
                    "verdict": review.get("verdict", ""),
                }
            except Exception:
                pass
    return results


def read_ai_analysis():
    html_dir = os.path.join(DATA_DIR, "html", "latest")
    if not os.path.isdir(html_dir):
        return None
    files = glob.glob(os.path.join(html_dir, "*.html"))
    if not files:
        return None
    latest = max(files, key=os.path.getmtime)
    with open(latest, "r", encoding="utf-8") as f:
        return f.read()


ANALYSIS_STORE = os.path.join(CE_ROOT, "content-data", "analysis")
ARTICLES_STORE = os.path.join(CE_ROOT, "content-data", "articles")

_running_jobs = {}
_RUNNING_JOBS_MAX_AGE = 3600 * 2   # Stage 2: 6h → 2h（更激进，避免长跑泄漏）
_RUNNING_JOBS_MAX_COUNT = 100       # Stage 2: 200 → 100


def _cleanup_old_jobs():
    """Remove completed/failed jobs older than _RUNNING_JOBS_MAX_AGE, keep recent ones."""
    if len(_running_jobs) < 10:
        return  # Stage 2: 20 → 10，更早开始 GC
    now = time.time()
    to_remove = []
    for jid, jdata in _running_jobs.items():
        if jdata.get("status") in ("done", "error"):
            start_str = jdata.get("start_time", "")
            try:
                start_ts = datetime.fromisoformat(start_str).timestamp() if start_str else 0
            except Exception:
                start_ts = 0
            if now - start_ts > _RUNNING_JOBS_MAX_AGE:
                to_remove.append(jid)
    for jid in to_remove:
        _running_jobs.pop(jid, None)
    # Hard cap: if still too many, remove oldest completed first
    if len(_running_jobs) > _RUNNING_JOBS_MAX_COUNT:
        completed = [(jid, jdata) for jid, jdata in _running_jobs.items()
                     if jdata.get("status") in ("done", "error")]
        completed.sort(key=lambda x: x[1].get("start_time", ""))
        for jid, _ in completed[:len(_running_jobs) - _RUNNING_JOBS_MAX_COUNT]:
            _running_jobs.pop(jid, None)


def _reparse_failed_insights(data: dict, fpath: str) -> dict:
    """Re-parse any model results that had _parse_error using the improved parser."""
    mr = data.get("model_results", {})
    changed = False
    for model_name, model_data in mr.items():
        insights = []
        if isinstance(model_data, dict):
            insights = model_data.get("insights", [])
        elif isinstance(model_data, list):
            insights = model_data

        if len(insights) == 1 and isinstance(insights[0], dict) and insights[0].get("_parse_error"):
            i0 = insights[0]
            raw_text = i0.get("core_insight", "") or (i0.get("title", "") + "\n" + i0.get("thesis", ""))
            try:
                from article.multi_model import _parse_insights
                new_insights = _parse_insights(raw_text.strip(), model_name)
                if len(new_insights) > 1 or (len(new_insights) == 1 and not new_insights[0].get("_parse_error")):
                    if isinstance(model_data, dict):
                        model_data["insights"] = new_insights
                    else:
                        mr[model_name] = {"insights": new_insights}
                    changed = True
                    print(f"[Reparse] {model_name}: recovered {len(new_insights)} insights from failed parse")
            except Exception as e:
                print(f"[Reparse] {model_name}: failed - {e}")

    if changed:
        total = 0
        succeeded = 0
        for mn, md in mr.items():
            ins = md.get("insights", []) if isinstance(md, dict) else md if isinstance(md, list) else []
            count = len(ins)
            if count > 0 and not (count == 1 and isinstance(ins[0], dict) and ins[0].get("_parse_error")):
                succeeded += 1
            total += count
        data["total_insights"] = total
        data["models_succeeded"] = succeeded
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"[Reparse] Saved updated file: {fpath}")
        except Exception as e:
            print(f"[Reparse] Save failed: {e}")
    return data


def _normalize_extra_points(raw) -> list[str]:
    """Validate/dedupe user-authored viewpoints from the browser.

    Browser maxlength/count checks are convenience only; API callers can bypass
    them. Keep one canonical server-side contract: array, max 20, max 500 chars,
    no blanks/duplicates/non-strings.
    """
    if not isinstance(raw, list):
        raise ValueError("extra_points must be an array")
    cleaned = []
    for point in raw[:20]:
        if not isinstance(point, str):
            continue
        point = point.strip()
        if point and point not in cleaned:
            cleaned.append(point[:500])
    return cleaned


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    # --- security helpers (stage 1, 2026-05-12) ---

    def _cors_origin(self):
        """根据请求 Origin 决定回写哪个 CORS 域。仅白名单允许；否则不发 CORS 头。"""
        origin = self.headers.get("Origin", "")
        if origin and origin in _ALLOWED_ORIGINS:
            return origin
        return ""

    def _send_security_headers(self):
        """调用必须在 send_response 之后、end_headers 之前。"""
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://browser.sentry-cdn.com https://js.sentry-cdn.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https:; "
            "worker-src 'self' blob:; "
            "frame-src https:; "
            "frame-ancestors 'none'"
        )
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send_error_json(self, status: int, message: str, extra_headers=None):
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _rate_ok(self, path: str) -> bool:
        """Stage 2 rate limit. client_id 优先用 Authorization 头，回退到 IP。"""
        cid = self.headers.get("Authorization", "") or (self.client_address[0] if self.client_address else "anon")
        if not _rate_allow(cid, path):
            self._send_error_json(429, "rate limit exceeded — please slow down")
            return False
        return True

    def _audit_actor(self) -> str:
        """提取操作者标识（供审计日志使用）。"""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return "bearer:" + auth[7:][:8] + "..."
        if auth.startswith("Basic "):
            try:
                decoded = _b64.b64decode(auth[6:]).decode("utf-8", "replace")
                user, _, _ = decoded.partition(":")
                return f"basic:{user}"
            except Exception:
                return "basic:?"
        return (self.client_address[0] if self.client_address else "anon")

    def _current_user(self):
        """返回当前请求的用户名（如果已鉴权）。检查顺序：cookie session → Bearer → Basic。"""
        # 1. Cookie session（浏览器交互入口）
        cookies = _parse_cookies(self.headers.get("Cookie", ""))
        tok = cookies.get(_SESSION_COOKIE)
        if tok:
            user = _session_valid(tok)
            if user:
                return user
        # 2. Bearer / Basic（API 客户端入口）
        auth = self.headers.get("Authorization", "")
        if _BEARER_TOKEN and auth.startswith("Bearer "):
            try:
                if _hmac.compare_digest(auth[7:].strip(), _BEARER_TOKEN):
                    return "bearer-client"
            except Exception:
                pass
        if _AUTH_USER and _AUTH_PASSWORD and auth.startswith("Basic "):
            try:
                decoded = _b64.b64decode(auth[6:]).decode("utf-8", "replace")
                user, _, pwd = decoded.partition(":")
                if _hmac.compare_digest(user, _AUTH_USER) and _hmac.compare_digest(pwd, _AUTH_PASSWORD):
                    return user
            except Exception:
                pass
        return None

    def _require_auth(self) -> bool:
        """检查 /api/* 鉴权。通过返回 True；否则自动发 401/503 并返回 False。
        如果服务器未配置任何认证，默认放行（依赖 Traefik / 网络层安全）。"""
        if not _AUTH_CONFIGURED:
            return True
        if self._current_user():
            return True
        # 重要：不再回写 WWW-Authenticate，避免浏览器对 fetch 弹 Basic 框
        # 浏览器前端 JS 收到 401 后自行显示登录页。curl/Bearer 客户端不依赖此头。
        self._send_error_json(401, "authentication required")
        return False

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_security_headers()
        if self._cors_origin():
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
            self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 全局鉴权 + 速率限制：所有 /api/* 必须带凭证 + 不超速
        # /api/login 是登录入口，跳过鉴权但仍走 rate limit（防暴力破解）
        if path.startswith("/api/"):
            if path != "/api/login":
                if not self._require_auth():
                    return
                # CSRF 校验：仅对 cookie session 用户（浏览器入口）强制检查
                # Bearer/Basic 认证的 API 客户端不需要 CSRF token
                if _AUTH_CONFIGURED:
                    cookies = _parse_cookies(self.headers.get("Cookie", ""))
                    sess_tok = cookies.get(_SESSION_COOKIE)
                    if sess_tok and _session_valid(sess_tok):
                        csrf_hdr = self.headers.get("X-CSRF-Token", "")
                        if not _csrf_validate(sess_tok, csrf_hdr):
                            self._send_error_json(403, "CSRF token invalid or missing")
                            return
            if not self._rate_ok(path):
                return

        # 请求体大小限制
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        if length < 0 or length > _MAX_BODY_SIZE:
            self._send_error_json(413, f"request body too large (max {_MAX_BODY_SIZE} bytes)")
            return
        body = {}
        if length > 0:
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = {}

        if path == "/api/analyze":
            self._start_analysis(body)
        elif path == "/api/generate-article":
            self._start_article_gen(body)
        elif path == "/api/review-article":
            self._start_review(body)
        elif path == "/api/revise-article":
            self._start_revision(body)
        elif path == "/api/format-article":
            self._format_article(body)
        elif path == "/api/publish-article":
            self._publish_article(body)
        elif path == "/api/record-metrics":
            self._record_metrics(body)
        elif path == "/api/add-competitor":
            self._add_competitor(body)
        elif path == "/api/add-competitor-article":
            self._add_competitor_article(body)
        elif path == "/api/competitors/scan":
            self._scan_competitors(body)
        elif path == "/api/competitors/seed":
            self._seed_competitors(body)
        elif path == "/api/competitors/set-rss":
            self._set_competitor_rss(body)
        elif path == "/api/competitors/delete":
            self._delete_competitor(body)
        elif path == "/api/repurpose":
            self._repurpose(body)
        elif path == "/api/generate-comments":
            self._generate_comments(body)
        elif path == "/api/scan-topics":
            self._scan_topics(body)
        elif path == "/api/recommendation/confirm":
            self._confirm_recommendation(body)
        elif path == "/api/recommendation/skip":
            self._skip_recommendation(body)
        elif path == "/api/set-feishu-webhook":
            self._set_feishu_webhook(body)
        elif path == "/api/test-feishu-webhook":
            self._test_feishu_webhook(body)
        elif path == "/api/video/generate-script":
            self._video_generate_script(body)
        elif path == "/api/video/script-from-article":
            self._video_script_from_article(body)
        elif path == "/api/project/update-stage":
            self._update_project_stage(body)
        elif path == "/api/verify-console":
            pwd = body.get("password", "")
            if not _CONSOLE_PASSWORD:
                self._json({"success": False, "error": "Console password not configured on server"})
            elif _hmac.compare_digest(pwd, _CONSOLE_PASSWORD):
                self._json({"success": True})
            else:
                self._json({"success": False, "error": "Invalid password"})
        elif path == "/api/save-api-keys":
            self._save_api_keys(body)
        elif path == "/api/generate-brief":
            self._generate_brief(body)
        elif path == "/api/generate-briefs-batch":
            self._generate_briefs_batch(body)
        elif path == "/api/translate":
            self._translate(body)
        elif path == "/api/generate-article-images":
            self._generate_article_images(body)
        elif path == "/api/image-models":
            self._list_image_models()
        elif path == "/api/generate-image-preview":
            self._generate_image_preview(body)
        elif path == "/api/extract-image-placeholders":
            self._extract_image_placeholders(body)
        elif path == "/api/apply-image":
            self._apply_image(body)
        elif path == "/api/fetch-page-texts-batch":
            self._fetch_page_texts_batch(body)
        elif path == "/api/article-structure":
            self._analyze_article_structure(body)
        elif path == "/api/login":
            self._handle_login(body)
        elif path == "/api/logout":
            self._handle_logout(body)
        else:
            self.send_error(404)

    def _handle_login(self, body):
        """Cookie session login (Stage 2.5)."""
        ip = self.client_address[0] if self.client_address else "0.0.0.0"
        allowed, wait_secs = _login_check(ip)
        if not allowed:
            _audit("anon", "auth.login_blocked", target=ip, detail=f"locked {wait_secs}s")
            self._send_error_json(429, f"too many login attempts, try again in {wait_secs} seconds")
            return
        user = (body.get("user") or "").strip()
        pwd = (body.get("password") or "")
        if not user or not pwd:
            self._send_error_json(400, "user and password required")
            return
        if not (_AUTH_USER and _AUTH_PASSWORD):
            self._send_error_json(503, "auth not configured on server")
            return
        try:
            ok = _hmac.compare_digest(user, _AUTH_USER) and _hmac.compare_digest(pwd, _AUTH_PASSWORD)
        except Exception:
            ok = False
        if not ok:
            _login_record_failure(ip)
            _audit("anon", "auth.login_failed", target=user[:32],
                   detail=ip)
            time.sleep(0.3)  # 简单防暴力：失败 300ms 延迟
            self._send_error_json(401, "invalid credentials")
            return
        _login_reset(ip)
        token = _session_create(user)
        body_out = json.dumps({"success": True, "user": user, "expires_in": _SESSION_LIFETIME}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_out)))
        # HttpOnly: 防 XSS 读取 cookie；Secure: 仅 HTTPS；SameSite=Lax: 防 CSRF
        self.send_header(
            "Set-Cookie",
            f"{_SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={_SESSION_LIFETIME}"
        )
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body_out)
        _audit(user, "auth.login_ok")

    def _handle_logout(self, body):
        """Revoke current session cookie."""
        cookies = _parse_cookies(self.headers.get("Cookie", ""))
        tok = cookies.get(_SESSION_COOKIE)
        if tok:
            _session_revoke(tok)
        body_out = b'{"success": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_out)))
        self.send_header(
            "Set-Cookie",
            f"{_SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        )
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body_out)

    def _generate_brief(self, body):
        """Generate a brief for a single news item."""
        title = body.get("title", "").strip()
        url = body.get("url", "")
        if not title:
            self._json({"error": "title is required"})
            return
        # Check cache first
        cached = _get_cached_briefs([title])
        if title in cached:
            self._json({"brief": cached[title], "cached": True})
            return
        # Generate
        result = _generate_and_cache_brief(title, url)
        if "brief" in result:
            self._json({"brief": result["brief"], "model": result.get("model", ""), "cached": False})
        else:
            self._json({"error": result.get("error", "生成失败")})

    def _generate_briefs_batch(self, body):
        """Generate briefs for multiple news items in background."""
        items = body.get("items", [])  # [{title, url}, ...]
        if not items:
            self._json({"error": "items is required"})
            return

        # Check cache, only generate for uncached
        titles = [it.get("title", "") for it in items if it.get("title")]
        cached = _get_cached_briefs(titles)
        to_generate = [it for it in items if it.get("title", "") not in cached]

        job_id = f"briefs_{int(time.time())}"
        _running_jobs[job_id] = {
            "status": "running", "type": "briefs",
            "total": len(to_generate), "done": 0,
            "cached_count": len(cached), "results": dict(cached),
        }

        def run():
            done = 0
            errors = 0
            last_model = ""
            for it in to_generate:
                t = it.get("title", "")
                u = it.get("url", "")
                if not t:
                    continue
                try:
                    r = _generate_and_cache_brief(t, u)
                    done += 1
                    if "brief" in r:
                        _running_jobs[job_id]["results"][t] = r["brief"]
                        last_model = r.get("model", last_model)
                    else:
                        errors += 1
                except Exception as e:
                    done += 1
                    errors += 1
                    print(f"[Brief Batch] Error for '{t[:30]}': {e}")
                _running_jobs[job_id]["done"] = done
                _running_jobs[job_id]["errors"] = errors
                _running_jobs[job_id]["model"] = last_model
            _running_jobs[job_id]["status"] = "done"

        threading.Thread(target=run, daemon=True).start()
        self._json({
            "job_id": job_id, "status": "started",
            "total": len(to_generate), "already_cached": len(cached),
            "cached_briefs": cached,
        })

    def _translate(self, body):
        """Translate text (typically English) to Chinese."""
        title = _cap_llm_input(body.get("title", "").strip(), _LLM_TOPIC_MAX)
        text = _cap_llm_input(body.get("text", "").strip(), _LLM_TEXT_MAX)
        if not title and not text:
            self._json({"error": "title or text required"})
            return
        content = f"标题：{title}" if title else ""
        if text:
            content += f"\n内容：{text}" if content else f"内容：{text}"
        prompt = (
            "将以下英文科技资讯翻译为中文，保持专业术语准确，语言自然流畅。"
            "只输出翻译结果，不要加额外说明。\n\n" + content
        )
        import httpx
        # Try DeepSeek → Gemini → TokenKey
        ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if ds_key:
            try:
                resp = httpx.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {ds_key}", "Content-Type": "application/json"},
                    json={"model": "deepseek-chat", "messages": [{"role": "user", "content": prompt}],
                          "max_tokens": 500, "temperature": 0.3},
                    timeout=20,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    translated = data["choices"][0]["message"]["content"].strip()
                    self._json({"translated": translated, "model": "deepseek"})
                    return
            except Exception as e:
                print(f"[Translate] DeepSeek failed: {e}")
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if gemini_key:
            try:
                resp = httpx.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}",
                    json={"contents": [{"parts": [{"text": prompt}]}],
                          "generationConfig": {"maxOutputTokens": 500, "temperature": 0.3}},
                    timeout=20,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    translated = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                    self._json({"translated": translated, "model": "gemini-flash"})
                    return
            except Exception as e:
                print(f"[Translate] Gemini failed: {e}")
        tk_key = os.environ.get("TOKENKEY_API_KEY", "")
        tk_base = os.environ.get("TOKENKEY_API_BASE", "https://api.tokenkey.dev/v1")
        if tk_key:
            try:
                resp = httpx.post(
                    f"{tk_base}/chat/completions",
                    headers={"Authorization": f"Bearer {tk_key}", "Content-Type": "application/json"},
                    json={"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": prompt}],
                          "max_tokens": 500, "temperature": 0.3},
                    timeout=25,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    translated = data["choices"][0]["message"]["content"].strip()
                    self._json({"translated": translated, "model": "claude-sonnet"})
                    return
            except Exception as e:
                print(f"[Translate] TokenKey failed: {e}")
        self._json({"error": "所有翻译模型均不可用，请检查 API 配置"})

    def _start_analysis(self, body):
        """Start multi-model analysis in background thread."""
        topic = _cap_llm_input(body.get("topic", "").strip(), _LLM_TOPIC_MAX)
        context = _cap_llm_input(body.get("context", ""), _LLM_CONTEXT_MAX)
        if not topic:
            self._json({"error": "topic is required"})
            return
        job_id = _launch_analysis_job(topic, context)
        self._json({"job_id": job_id, "status": "started", "topic": topic})

    def _start_article_gen(self, body):
        """Generate article from analysis results or selected insights."""
        selected_insights = body.get("selected_insights", [])
        extra_points = body.get("extra_points", [])
        topic = body.get("topic", "")
        analysis_file = body.get("analysis_file", "")
        project_id = body.get("project_id")

        if not isinstance(selected_insights, list):
            self._json({"error": "selected_insights must be an array"})
            return
        try:
            extra_points = _normalize_extra_points(extra_points)
        except ValueError as exc:
            self._json({"error": str(exc)})
            return

        if not selected_insights and not analysis_file and not extra_points:
            self._json({"error": "need selected_insights, analysis_file, or extra_points"})
            return

        job_id = f"article_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "article", "topic": topic, "project_id": project_id}

        if project_id:
            _update_project(project_id, stage="writing")
            _add_project_event(
                project_id,
                "writing_started",
                f"基于 {len(selected_insights)} 个模型洞察 + {len(extra_points)} 个用户观点开始写作",
            )

        def run():
            try:
                from article.generator import generate_article, save_article
                if selected_insights or extra_points:
                    analysis = {
                        "topic": topic,
                        "selected_insights": selected_insights,
                        "total_insights": len(selected_insights),
                    }
                else:
                    with open(analysis_file, "r", encoding="utf-8") as f:
                        analysis = json.load(f)
                article = generate_article(analysis, extra_points=extra_points)

                # 生成配图并嵌入文章
                updated_content, img_results = _generate_and_embed_images(article["content"])
                article["content"] = updated_content
                if img_results:
                    article["images"] = [i for i in img_results if "filename" in i]

                filepath = save_article(article)
                _running_jobs[job_id] = {
                    "status": "done",
                    "type": "article",
                    "topic": topic,
                    "result": {k: v for k, v in article.items() if k != "content"},
                    "content_preview": article["content"][:1000],
                    "file": filepath,
                    "project_id": project_id,
                }
                if project_id:
                    # stage 停在 writing — 让用户阅读文章后手动点"发起机审"
                    _update_project(project_id, stage="writing",
                                    article_file=filepath,
                                    article_title=article.get("title", ""))
                    _add_project_event(project_id, "article_done",
                                       f"文章完成: {article.get('title', '')}")
                _send_feishu_notification(
                    f"✍️ 文章生成完成: {topic}",
                    f"**话题**: {topic}\n"
                    f"**标题**: {article.get('title', '未知')}\n"
                    f"**字数**: {len(article.get('content', ''))}\n\n"
                    f"🔗 [查看详情]({os.environ.get('DASHBOARD_URL', 'https://content.orbitlogic.dev')})",
                )
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic, "project_id": project_id}
                if project_id:
                    _update_project(project_id, stage="failed")
                    _add_project_event(project_id, "writing_failed", str(e)[:500])
                _send_feishu_notification(
                    f"❌ 文章生成失败: {topic}",
                    f"**话题**: {topic}\n**错误**: {str(e)[:200]}",
                )

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started", "topic": topic})

    def _generate_article_images(self, body):
        """Generate images for an existing article's [IMAGE: ...] placeholders."""
        article_file = body.get("article_file", "")
        project_id = body.get("project_id")
        if not article_file or not os.path.exists(article_file):
            self._json({"error": "article_file not found"})
            return

        job_id = f"imagegen_{int(time.time())}"
        _running_jobs[job_id] = {"status": "running", "type": "imagegen", "project_id": project_id}

        def run():
            try:
                import re as _re
                with open(article_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Check if there are [IMAGE: ...] placeholders
                placeholders = _re.findall(r'\[IMAGE:\s*[^\]]+\]', content)
                if not placeholders:
                    _running_jobs[job_id] = {"status": "done", "type": "imagegen",
                                             "message": "No [IMAGE:] placeholders found", "images": []}
                    return

                # Generate images and embed
                updated_content, img_results = _generate_and_embed_images(content)

                # Write back
                with open(article_file, "w", encoding="utf-8") as f:
                    f.write(updated_content)

                successful = [i for i in img_results if "filename" in i]
                _running_jobs[job_id] = {
                    "status": "done", "type": "imagegen",
                    "message": f"Generated {len(successful)} images",
                    "images": successful, "project_id": project_id,
                }
                if project_id:
                    _add_project_event(project_id, "images_generated",
                                       f"为文章生成了 {len(successful)} 张配图")
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e), "project_id": project_id}
                print(f"[ImageGen] Error: {e}")

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _list_image_models(self):
        """Return available image generation models."""
        from article.image_gen import available_models
        self._json({"models": available_models()})

    def _extract_image_placeholders(self, body):
        """Extract [IMAGE: ...] placeholders from an article file."""
        article_file = body.get("article_file", "")
        if not article_file or not os.path.exists(article_file):
            self._json({"error": "article_file not found"})
            return
        import re as _re
        with open(article_file, "r", encoding="utf-8") as f:
            content = f.read()
        placeholders = _re.findall(r'\[IMAGE:\s*(.+?)\]', content)
        self._json({"placeholders": placeholders, "count": len(placeholders)})

    def _apply_image(self, body):
        """Embed a chosen preview image into the article file, replacing its
        [IMAGE: placeholder] with a markdown image reference.

        入参: {article_file, placeholder, image_path}
        - article_file 必须落在 content-data/articles 白名单内（复用 _is_safe_detail_path）
        - image_path 必须落在 _IMAGE_STORE 内，防止读取任意文件
        """
        article_file = body.get("article_file", "")
        placeholder = (body.get("placeholder") or "").strip()
        image_path = body.get("image_path", "")

        if not article_file or not _is_safe_detail_path(article_file) or not os.path.exists(article_file):
            self._json({"error": "article_file not found or access denied"})
            return
        if not placeholder:
            self._json({"error": "placeholder is required"})
            return
        if not image_path:
            self._json({"error": "image_path is required"})
            return

        real_img = os.path.realpath(image_path)
        real_store = os.path.realpath(_IMAGE_STORE)
        if not (real_img == real_store or real_img.startswith(real_store + os.sep)):
            self._json({"error": "image_path access denied"})
            return
        if not os.path.isfile(real_img):
            self._json({"error": "image file not found"})
            return

        filename = os.path.basename(real_img)

        import re as _re
        try:
            with open(article_file, "r", encoding="utf-8") as f:
                content = f.read()

            desc_escaped = _re.escape(placeholder)
            pattern = r'\[IMAGE:\s*' + desc_escaped + r'\]'
            replacement = '![{}](/api/article-image?file={})'.format(placeholder, filename)
            new_content, n = _re.subn(pattern, replacement, content, count=1)

            if n == 0:
                self._json({"error": "placeholder not found in article (可能已被替换或描述不一致)"})
                return

            _atomic_write_text(article_file, new_content)
            _audit("dashboard", "image.apply", target=article_file, detail=f"placeholder={placeholder[:80]} file={filename}")
            self._json({"success": True, "filename": filename, "article_file": article_file})
        except Exception as e:
            self._json({"error": str(e)})

    def _generate_image_preview(self, body):
        """Generate a single image preview with custom prompt and model selection.
        Returns a job_id; poll /api/job to get the result with preview_base64."""
        prompt = body.get("prompt", "").strip()
        model = body.get("model", "auto")
        if not prompt:
            self._json({"error": "prompt is required"})
            return

        job_id = f"imgpreview_{int(time.time())}_{hash(prompt) % 10000}"
        _running_jobs[job_id] = {"status": "running", "type": "imagegen"}

        def run():
            try:
                from article.image_gen import generate_image_preview
                result = generate_image_preview(prompt, model=model)
                if "error" in result:
                    _running_jobs[job_id] = {"status": "error", "error": result["error"]}
                else:
                    _running_jobs[job_id] = {
                        "status": "done", "type": "imagegen",
                        "result": {
                            "preview_base64": result.get("preview_base64", ""),
                            "filename": result.get("filename", ""),
                            "path": result.get("path", ""),
                            "model": result.get("model", ""),
                            "generation_time": result.get("generation_time", 0),
                            "size_bytes": result.get("size_bytes", 0),
                            "prompt": prompt,
                        }
                    }
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e)}
                print(f"[ImagePreview] Error: {e}")

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started", "model": model})

    def _analyze_article_structure(self, body):
        """Analyze article argument structure and logical flow using LLM."""
        import httpx

        article_file = body.get("file", "")
        if not article_file:
            self._send_error_json(400, "file parameter required")
            return

        # Read article content — resolve path same as article-detail GET
        fpath = article_file
        if not os.path.isabs(fpath):
            fpath = os.path.join(CE_ROOT, fpath)
        fpath = os.path.realpath(fpath)
        if not _is_safe_detail_path(fpath) or not os.path.isfile(fpath):
            self._send_error_json(404, "article file not found")
            return

        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        # Strip front matter
        if content.startswith("---"):
            fm_end = content.index("---", 3) if "---" in content[3:] else -1
            if fm_end > 0:
                content = content[fm_end + 3:].strip()

        prompt = f"""你是一位资深编辑。请分析以下文章的论点结构和逻辑链。

要求：
1. 将文章分成逻辑段落（不是按标题，而是按论点），每段提炼一句核心论点
2. 分析段落之间的逻辑关系（引出/支撑/递进/转折/对比/举例/总结）
3. 评估整体逻辑紧凑度（1-10分）
4. 如果有逻辑薄弱点或"堆砌感"，指出具体位置

请严格用以下 JSON 格式返回（不要加 markdown 代码块标记）：
{{
  "sections": [
    {{
      "id": 1,
      "title": "段落概括（5-10字）",
      "core_point": "这一段的核心论点（一句话）",
      "relation_to_next": "与下一段的逻辑关系（引出/支撑/递进/转折/对比/举例/总结/无）",
      "relation_strength": "强/中/弱"
    }}
  ],
  "logic_score": 8,
  "logic_comment": "整体逻辑评价（1-2句话）",
  "weak_points": ["薄弱点1描述", "薄弱点2描述"],
  "flow_summary": "一句话概括全文论证路径，如：提出现象→分析原因→对比案例→得出结论"
}}

文章内容：
{content[:12000]}"""

        result = None
        model_used = ""

        # 1. Try DeepSeek (fast)
        ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if ds_key:
            try:
                resp = httpx.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {ds_key}", "Content-Type": "application/json"},
                    json={"model": "deepseek-chat", "messages": [{"role": "user", "content": prompt}],
                          "max_tokens": 2000, "temperature": 0.3},
                    timeout=30,
                )
                if resp.status_code == 200:
                    text = resp.json()["choices"][0]["message"]["content"].strip()
                    model_used = "deepseek"
                    result = text
            except Exception as e:
                print(f"[Structure] DeepSeek failed: {e}")

        # 2. Fallback: TokenKey Claude
        if not result:
            tk_key = os.environ.get("TOKENKEY_API_KEY", "")
            tk_base = os.environ.get("TOKENKEY_API_BASE", "https://api.tokenkey.dev/v1")
            if tk_key:
                try:
                    resp = httpx.post(
                        f"{tk_base}/chat/completions",
                        headers={"Authorization": f"Bearer {tk_key}", "Content-Type": "application/json"},
                        json={"model": "claude-sonnet-4-20250514",
                              "messages": [{"role": "user", "content": prompt}],
                              "max_tokens": 2000, "temperature": 0.3},
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        text = resp.json()["choices"][0]["message"]["content"].strip()
                        model_used = "claude-sonnet"
                        result = text
                except Exception as e:
                    print(f"[Structure] TokenKey failed: {e}")

        if not result:
            self._send_error_json(500, "所有模型均不可用")
            return

        # Parse JSON from LLM response
        import re as _re
        # Strip markdown code block if present
        result = _re.sub(r'^```(?:json)?\s*', '', result)
        result = _re.sub(r'\s*```$', '', result)

        try:
            parsed = json.loads(result)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            match = _re.search(r'\{[\s\S]*\}', result)
            if match:
                try:
                    parsed = json.loads(match.group())
                except json.JSONDecodeError:
                    parsed = {"raw": result, "parse_error": True}
            else:
                parsed = {"raw": result, "parse_error": True}

        parsed["model"] = model_used
        self._json(parsed)

    def _fetch_page_texts_batch(self, body):
        """Batch fetch and cache page texts for a list of URLs."""
        urls = body.get("urls", [])
        if not urls:
            self._json({"error": "urls list required"})
            return
        urls = urls[:80]  # Cap at 80

        # Return already-cached texts immediately
        cached = _get_cached_page_texts(urls)
        uncached = [u for u in urls if u not in cached]

        if not uncached:
            self._json({"cached": len(cached), "fetching": 0, "texts": cached})
            return

        job_id = f"pagetext_{int(time.time())}"
        _running_jobs[job_id] = {
            "status": "running", "type": "pagetext",
            "total": len(uncached), "done": 0, "texts": {},
        }

        def run():
            done = 0
            for url in uncached:
                try:
                    result = _fetch_and_cache_page_text(url)
                    _running_jobs[job_id]["texts"][url] = {
                        "text": result["text"][:3000],  # Truncate in job result
                        "status": result["status"],
                    }
                except Exception as e:
                    _running_jobs[job_id]["texts"][url] = {"text": "", "status": "error"}
                done += 1
                _running_jobs[job_id]["done"] = done
                time.sleep(0.3)  # Throttle
            _running_jobs[job_id]["status"] = "done"
            print(f"[PageText] Batch done: {done}/{len(uncached)} fetched")

        threading.Thread(target=run, daemon=True).start()
        self._json({
            "job_id": job_id,
            "cached": len(cached),
            "fetching": len(uncached),
            "texts": cached,
        })

    def _start_review(self, body):
        """Review an article."""
        article_file = body.get("article_file", "")
        project_id = body.get("project_id")
        if not article_file or not os.path.exists(article_file):
            self._json({"error": "article_file not found"})
            return

        job_id = f"review_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "review", "project_id": project_id}

        def run():
            try:
                from article.reviewer import review_article, save_review
                with open(article_file, "r", encoding="utf-8") as f:
                    content = f.read()
                title = ""
                if "---" in content:
                    parts = content.split("---", 2)
                    if len(parts) >= 3:
                        for line in parts[1].split("\n"):
                            if line.startswith("title:"):
                                title = line.split(":", 1)[1].strip()
                        content = parts[2]

                review = review_article(content, title)
                review_path = save_review(review, article_file)
                _running_jobs[job_id] = {
                    "status": "done",
                    "type": "review",
                    "result": review,
                    "file": review_path,
                    "project_id": project_id,
                }
                # 审核完成后：停留在 review 阶段，等用户手动决策
                if project_id:
                    verdict = review.get("verdict", "unknown") if isinstance(review, dict) else "unknown"
                    score = review.get("overall_score", 0) if isinstance(review, dict) else 0
                    _update_project(project_id, stage="review",
                                    review_file=review_path,
                                    review_score=score,
                                    review_verdict=verdict)
                    _add_project_event(project_id, "review_done",
                                       f"AI审核完成: {score}分/{verdict}，等待人工决策")
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e), "project_id": project_id}
                if project_id:
                    _add_project_event(project_id, "review_failed", str(e)[:500])

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _start_revision(self, body):
        """Revise an article based on review suggestions."""
        article_file = body.get("article_file", "")
        review_file = body.get("review_file", "")
        project_id = body.get("project_id")
        extra_instructions = body.get("extra_instructions", [])

        if not article_file or not os.path.exists(article_file):
            self._json({"error": "article_file not found"})
            return
        if not review_file or not os.path.exists(review_file):
            self._json({"error": "review_file not found"})
            return

        job_id = f"revise_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "revision", "project_id": project_id}

        def run():
            try:
                from article.generator import revise_article, save_revised_article

                with open(article_file, "r", encoding="utf-8") as f:
                    content = f.read()
                with open(review_file, "r", encoding="utf-8") as f:
                    review = json.load(f)

                title = ""
                if content.startswith("---"):
                    parts = content.split("---", 2)
                    if len(parts) >= 3:
                        for line in parts[1].split("\n"):
                            if line.startswith("title:"):
                                title = line.split(":", 1)[1].strip()

                result = revise_article(
                    article_content=content,
                    review=review,
                    article_title=title,
                    extra_instructions=extra_instructions if extra_instructions else None,
                )
                revised_path = save_revised_article(result, article_file)

                _running_jobs[job_id] = {
                    "status": "done",
                    "type": "revision",
                    "result": {k: v for k, v in result.items() if k != "content"},
                    "content_preview": result["content"][:1000],
                    "file": revised_path,
                    "project_id": project_id,
                }

                if project_id:
                    # Update article file to revised version, re-enter review
                    _update_project(project_id, stage="review", article_file=revised_path)
                    _add_project_event(project_id, "revision_done",
                                       f"文章修订完成: {result.get('title', '')} "
                                       f"({result.get('word_count', 0)}字, "
                                       f"{result.get('generation_time', 0)}s)")
                    # Auto re-review the revised article
                    topic = ""
                    row = _get_project(project_id)
                    if row:
                        topic = row.get("topic", "")
                    _auto_review_article(revised_path, project_id, topic)

                _send_feishu_notification(
                    f"✏️ 文章修订完成",
                    f"**标题**: {result.get('title', '')}\n"
                    f"**字数**: {result.get('word_count', 0)}\n"
                    f"**修改项**: {result.get('revision_suggestions_count', 0)}条建议已吸收",
                )
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e), "project_id": project_id}
                if project_id:
                    _add_project_event(project_id, "revision_failed", str(e)[:500])
                print(f"[Revision] Error: {e}")

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _publish_article(self, body):
        """Publish article to platform (WeChat/analytics record)."""
        try:
            title = body.get("title", "").strip()
            platform = body.get("platform", "wechat")
            project_id = body.get("project_id")
            article_file = body.get("article_file", "")
            dry_run = body.get("dry_run", False)

            if not title and not project_id:
                self._json({"error": "title or project_id required"})
                return

            if project_id and not article_file:
                row = _get_project(int(project_id))
                if row:
                    article_file = row.get("article_file", "")
                    if not title:
                        title = row.get("topic", "")

            if platform == "wechat":
                wechat_cfg = self._load_wechat_config()
                if wechat_cfg and wechat_cfg.get("app_id") and wechat_cfg.get("app_secret"):
                    from article.wechat_publisher import publish_article as wechat_publish
                    result = wechat_publish(
                        article_md_path=article_file,
                        app_id=wechat_cfg["app_id"],
                        app_secret=wechat_cfg["app_secret"],
                        author=wechat_cfg.get("author", "蔚满漫行记"),
                        thumb_media_id=wechat_cfg.get("default_thumb_media_id", ""),
                        dry_run=dry_run,
                        draft_only=True,  # 个人订阅号无 freepublish 权限，推到草稿箱
                    )
                    if not dry_run and project_id:
                        _update_project(int(project_id), stage="published")
                        _add_project_event(int(project_id), "published",
                                           f"已推送到微信草稿箱: {result.get('draft_media_id', '')}")
                    if not dry_run:
                        _audit(self._audit_actor(), "article.publish", target=str(project_id or title)[:120],
                               detail=f"platform=wechat draft={result.get('draft_media_id','')}")
                    self._json({"success": True, "platform": "wechat", **result})
                    return

            from article.analytics import add_published_article
            aid = add_published_article(
                title,
                publish_date=body.get("publish_date"),
                platform=platform,
                article_file=article_file,
            )
            if project_id:
                _update_project(int(project_id), stage="published")
                _add_project_event(int(project_id), "published",
                                   f"已记录发布: {platform}")
            self._json({
                "success": True,
                "article_id": aid,
                "platform": platform,
                "wechat_configured": False,
                "hint": "微信凭据未配置，仅记录发布。配置 config.yaml wechat.app_id/app_secret 后可直接推送。",
            })
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _load_wechat_config(self):
        """Load WeChat config from env vars (preferred) or content-engine/config.yaml."""
        # Env vars take priority (more secure, no secrets in image)
        env_cfg = {
            "app_id": os.environ.get("WECHAT_APP_ID", ""),
            "app_secret": os.environ.get("WECHAT_APP_SECRET", ""),
            "default_thumb_media_id": os.environ.get("WECHAT_THUMB_MEDIA_ID", ""),
            "author": os.environ.get("WECHAT_AUTHOR", ""),
        }
        if env_cfg["app_id"] and env_cfg["app_secret"]:
            return env_cfg
        # Fallback to config.yaml
        try:
            import yaml
            cfg_path = os.path.join(CE_ROOT, "config.yaml")
            with open(cfg_path, "r") as f:
                cfg = yaml.safe_load(f)
            return cfg.get("wechat", {})
        except Exception:
            return {}

    def _record_metrics(self, body):
        """Record metrics for a published article."""
        try:
            from article.analytics import record_metrics
            aid = body.get("article_id")
            if not aid:
                self._json({"error": "article_id required"})
                return
            record_metrics(
                int(aid),
                reads=body.get("reads", 0),
                likes=body.get("likes", 0),
                favorites=body.get("favorites", 0),
                shares=body.get("shares", 0),
                comments=body.get("comments", 0),
                new_followers=body.get("new_followers", 0),
                read_rate=body.get("read_rate", 0),
            )
            self._json({"success": True})
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _add_competitor(self, body):
        """Add a competitor account."""
        try:
            from article.analytics import add_competitor
            name = body.get("name", "").strip()
            if not name:
                self._json({"error": "name required"})
                return
            cid = add_competitor(
                name,
                wechat_id=body.get("wechat_id", ""),
                category=body.get("category", ""),
                notes=body.get("notes", ""),
                rss_url=body.get("rss_url", ""),
                feed_type=body.get("feed_type", "rss"),
            )
            self._json({"success": True, "competitor_id": cid})
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _add_competitor_article(self, body):
        """Add a competitor article."""
        try:
            from article.analytics import add_competitor_article
            cid = body.get("competitor_id")
            title = body.get("title", "").strip()
            if not cid or not title:
                self._json({"error": "competitor_id and title required"})
                return
            add_competitor_article(
                int(cid),
                title,
                url=body.get("url", ""),
                publish_date=body.get("publish_date", ""),
                estimated_reads=body.get("estimated_reads", 0),
                likes=body.get("likes", 0),
                topic_tags=body.get("topic_tags", ""),
                title_style=body.get("title_style", ""),
                notes=body.get("notes", ""),
            )
            self._json({"success": True})
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _scan_competitors(self, body):
        """Trigger competitor RSS scan + AI insight generation."""
        job_id = f"comp_scan_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "competitor_scan"}

        def run():
            try:
                from article.analytics import (scan_all_competitor_rss,
                                               generate_competitive_insights,
                                               seed_default_competitors)
                seed_default_competitors()
                results = scan_all_competitor_rss(limit_per=30)
                new_total = sum(r.get("new", 0) for r in results if "new" in r)
                insights = generate_competitive_insights()
                _running_jobs[job_id] = {
                    "status": "done", "type": "competitor_scan",
                    "scan_results": results,
                    "new_articles": new_total,
                    "insights_count": len(insights),
                }
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "type": "competitor_scan",
                                         "error": str(e)[:500]}

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _seed_competitors(self, body):
        """Seed default competitor fleet."""
        try:
            from article.analytics import seed_default_competitors
            count = seed_default_competitors()
            self._json({"success": True, "seeded": count})
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _set_competitor_rss(self, body):
        """Set RSS URL for a competitor."""
        try:
            from article.analytics import update_competitor_rss
            cid = body.get("competitor_id")
            rss_url = body.get("rss_url", "").strip()
            if not cid:
                self._json({"error": "competitor_id required"})
                return
            update_competitor_rss(int(cid), rss_url,
                                  feed_type=body.get("feed_type", ""))
            self._json({"success": True})
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _delete_competitor(self, body):
        """Delete a competitor."""
        try:
            from article.analytics import delete_competitor
            cid = body.get("competitor_id")
            if not cid:
                self._json({"error": "competitor_id required"})
                return
            delete_competitor(int(cid))
            _audit(self._audit_actor(), "competitor.delete", target=str(cid))
            self._json({"success": True})
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def _scan_topics(self, body):
        """Manually trigger a topic scan."""
        job_id = f"scan_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "scan"}

        def run():
            try:
                from article.topic_detector import scan_and_recommend
                results = scan_and_recommend()
                _running_jobs[job_id] = {
                    "status": "done",
                    "type": "scan",
                    "result": {"recommendations": results, "count": len(results)},
                }
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e)}

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _confirm_recommendation(self, body):
        """Confirm a recommended topic -> start multi-model analysis."""
        topic = body.get("topic", "").strip()
        context = body.get("context", "")
        if not topic:
            self._json({"error": "topic required"})
            return
        # 从待审批队列移除
        _pending_approvals.pop(topic, None)
        job_id = _launch_analysis_job(topic, context)
        self._json({"job_id": job_id, "status": "started", "topic": topic})

    def _skip_recommendation(self, body):
        """Skip a recommended topic."""
        topic = body.get("topic", "").strip()
        if topic:
            _skipped_topics.add(topic)
            _save_skipped_topics()
            # 从待审批队列移除
            _pending_approvals.pop(topic, None)
        self._json({"success": True, "skipped": topic})

    def _set_feishu_webhook(self, body):
        global FEISHU_WEBHOOK_URL
        url = body.get("url", "").strip()
        # SSRF 防护：拒绝内网；空字符串允许（用于禁用通知）
        if url and _is_private_or_invalid_url(url):
            self._json({"error": "webhook url not allowed (must be public https)"})
            return
        # 进一步限制 host 到飞书官方域名（避免被改到任意外网回调）
        if url:
            try:
                host = _sec_urlparse(url).hostname or ""
                if not (host.endswith("feishu.cn") or host.endswith("larksuite.com")):
                    self._json({"error": "webhook url must be on feishu.cn or larksuite.com"})
                    return
            except Exception:
                self._json({"error": "invalid webhook url"})
                return
        FEISHU_WEBHOOK_URL = url
        _audit(self._audit_actor(), "feishu.set_webhook", detail=("disabled" if not url else "set"))
        self._json({"success": True, "url": url})

    def _test_feishu_webhook(self, body):
        _send_feishu_notification("🧪 测试通知", "AI Radar 通知已连通！\n分析完成后将自动推送到这里。")
        self._json({"success": True, "sent": bool(FEISHU_WEBHOOK_URL)})

    def _video_generate_script(self, body):
        topic = _cap_llm_input(body.get("topic", "").strip(), _LLM_TOPIC_MAX)
        context = _cap_llm_input(body.get("context", ""), _LLM_CONTEXT_MAX)
        platform = body.get("platform", "douyin")
        duration = body.get("duration", 60)
        if not topic:
            self._json({"error": "topic required"})
            return
        job_id = f"vscript_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "video_script"}

        def run():
            try:
                from article.video_workbench import generate_video_script, save_script
                result = generate_video_script(topic, context, platform, duration)
                filepath = save_script(result)
                _running_jobs[job_id] = {"status": "done", "type": "video_script", "result": result, "file": filepath}
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e)}

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _video_script_from_article(self, body):
        article_file = body.get("article_file", "")
        article_content = body.get("article_content", "")
        article_title = body.get("article_title", "")
        if not article_content and article_file:
            try:
                with open(article_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                article_content = data.get("content", data.get("article", ""))
                article_title = article_title or data.get("title", "")
            except Exception:
                pass
        if not article_content:
            self._json({"error": "article_content or article_file required"})
            return
        job_id = f"vart_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "video_from_article"}

        def run():
            try:
                from article.video_workbench import generate_script_from_article, save_script
                result = generate_script_from_article(article_content, article_title)
                filepath = save_script(result)
                _running_jobs[job_id] = {"status": "done", "type": "video_from_article", "result": result, "file": filepath}
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e)}

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _update_project_stage(self, body):
        pid = body.get("project_id")
        stage = body.get("stage", "")
        notes = body.get("notes", "")
        if not pid or not stage:
            self._json({"error": "project_id and stage required"})
            return
        valid_stages = ["analysis", "insights", "writing", "review", "human_review", "ready", "published", "failed", "archived"]
        if stage not in valid_stages:
            self._json({"error": f"invalid stage, must be one of: {valid_stages}"})
            return
        updates = {"stage": stage}
        if notes:
            updates["notes"] = notes
        _update_project(pid, **updates)
        _add_project_event(pid, "stage_change", f"阶段变更: → {stage}")
        self._json({"success": True, "project_id": pid, "stage": stage})

    def _save_api_keys(self, body):
        """Save API keys to .env file and update os.environ. Requires console password."""
        pwd = body.get("password", "")
        if not _CONSOLE_PASSWORD:
            self._json({"error": "Console password not configured on server"})
            return
        try:
            if not _hmac.compare_digest(pwd, _CONSOLE_PASSWORD):
                self._json({"error": "Authentication required"})
                return
        except Exception:
            self._json({"error": "Authentication required"})
            return
        env_path = os.path.join(CE_ROOT, ".env")
        existing = {}
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        existing[k.strip()] = v.strip().strip('"').strip("'")

        anthropic_key = body.get("anthropic_key", "").strip()
        openai_key = body.get("openai_key", "").strip()
        airouter_key = body.get("airouter_key", "").strip()
        airouter_base = body.get("airouter_base", "").strip()
        updated = False

        if airouter_key:
            existing["AIROUTER_API_KEY"] = airouter_key
            os.environ["AIROUTER_API_KEY"] = airouter_key
            updated = True
        if airouter_base:
            existing["AIROUTER_API_BASE"] = airouter_base
            os.environ["AIROUTER_API_BASE"] = airouter_base
            updated = True
        if anthropic_key:
            existing["ANTHROPIC_API_KEY"] = anthropic_key
            os.environ["ANTHROPIC_API_KEY"] = anthropic_key
            updated = True
        if openai_key:
            existing["OPENAI_API_KEY"] = openai_key
            os.environ["OPENAI_API_KEY"] = openai_key
            updated = True

        if updated:
            content = "# Content Engine Environment Variables\n# Auto-generated by Dashboard\n\n"
            for k, v in existing.items():
                content += f'{k}="{v}"\n'
            try:
                _atomic_write_text(env_path, content)
            except Exception as e:
                self._json({"error": "failed to persist .env"})
                print(f"[SECURITY] .env atomic write failed: {e}", flush=True)
                return
            # 审计：记录哪些 key 被改（不记录值）
            changed = [k for k, val in [
                ("AIROUTER_API_KEY", airouter_key), ("AIROUTER_API_BASE", airouter_base),
                ("ANTHROPIC_API_KEY", anthropic_key), ("OPENAI_API_KEY", openai_key)
            ] if val]
            _audit(self._audit_actor(), "config.save_api_keys", detail=",".join(changed))
            self._json({"success": True, "message": "API keys saved. Will take effect on next scan."})
        else:
            self._json({"error": "No keys provided"})

    def _generate_comments(self, body):
        """Generate thoughtful comments for a target article."""
        title = body.get("title", "").strip()
        if not title:
            self._json({"error": "title required"})
            return

        job_id = f"comment_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "comment"}

        def run():
            try:
                from article.comment_engine import generate_comments, save_comments
                result = generate_comments(
                    article_title=title,
                    article_summary=body.get("summary", ""),
                    article_url=body.get("url", ""),
                    article_author=body.get("author", ""),
                )
                save_comments(result)
                _running_jobs[job_id] = {
                    "status": "done",
                    "type": "comment",
                    "result": result,
                }
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e)}

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _repurpose(self, body):
        """Repurpose article for another platform."""
        article_file = body.get("article_file", "")
        platform = body.get("platform", "")
        if not article_file or not os.path.exists(article_file):
            self._json({"error": "article_file not found"})
            return
        if not platform:
            self._json({"error": "platform required (video_script/zhihu_answer/moments_snippet)"})
            return

        job_id = f"repurpose_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "repurpose", "platform": platform}

        def run():
            try:
                from article.cross_platform import repurpose, save_repurposed
                with open(article_file, "r", encoding="utf-8") as f:
                    content = f.read()
                title = ""
                if content.startswith("---"):
                    parts = content.split("---", 2)
                    if len(parts) >= 3:
                        for line in parts[1].split("\n"):
                            if line.startswith("title:"):
                                title = line.split(":", 1)[1].strip()
                        content = parts[2]
                result = repurpose(content, title, platform)
                filepath = save_repurposed(result)
                _running_jobs[job_id] = {
                    "status": "done",
                    "type": "repurpose",
                    "result": result,
                    "file": filepath,
                }
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e)}

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started"})

    def _format_article(self, body):
        """Format article with WeChat OA template, optionally generating images."""
        article_file = body.get("article_file", "")
        template = body.get("template", "analysis")
        author = body.get("author", "")
        generate_images = body.get("generate_images", False)

        if not article_file or not os.path.exists(article_file):
            self._json({"error": "article_file not found"})
            return

        try:
            from article.formatter import format_article, get_templates
            with open(article_file, "r", encoding="utf-8") as f:
                md_content = f.read()

            title = ""
            if md_content.startswith("---"):
                parts = md_content.split("---", 2)
                if len(parts) >= 3:
                    for line in parts[1].split("\n"):
                        if line.startswith("title:"):
                            title = line.split(":", 1)[1].strip()

            import time
            formatted = format_article(
                md_content,
                template=template,
                title=title,
                author=author,
                date=time.strftime("%Y-%m-%d"),
            )

            image_results = []
            if generate_images:
                try:
                    from article.image_gen import generate_article_images, replace_placeholders_with_images
                    image_results = generate_article_images(md_content, max_images=4)
                    if image_results:
                        formatted = replace_placeholders_with_images(formatted, image_results)
                except Exception as img_err:
                    image_results = [{"error": str(img_err)}]

            self._json({
                "html": formatted,
                "template": template,
                "title": title,
                "templates": get_templates(),
                "images": image_results,
            })
        except Exception as e:
            self._json({"error": _safe_err(e)})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        date = params.get("date", [None])[0]

        # /api/me 在鉴权之前响应，前端用它做"是否已登录"探测
        if path == "/api/me":
            user = self._current_user() if _AUTH_CONFIGURED else "anonymous"
            resp = {"user": user, "auth_configured": _AUTH_CONFIGURED}
            # 如果是 cookie session 用户，返回 CSRF token 供前端后续 POST 使用
            if user:
                cookies = _parse_cookies(self.headers.get("Cookie", ""))
                sess_tok = cookies.get(_SESSION_COOKIE)
                if sess_tok and _session_valid(sess_tok):
                    resp["csrf_token"] = _csrf_generate(sess_tok)
            self._json(resp)
            return

        # 全局鉴权 + 速率限制：所有 /api/* 必须带凭证 + 不超速
        if path.startswith("/api/"):
            if not self._require_auth():
                return
            if not self._rate_ok(path):
                return

        # 图片文件服务 — 直接返回二进制，不走 JSON
        if path == "/api/article-image":
            file_param = params.get("file", [None])[0]
            if not file_param:
                self._json({"error": "file parameter required"})
                return
            safe_name = os.path.basename(file_param)  # 防止目录穿越
            img_path = os.path.join(_IMAGE_STORE, safe_name)
            if not os.path.isfile(img_path):
                self.send_error(404, "Image not found")
                return
            ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
            mime_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                        "gif": "image/gif", "webp": "image/webp"}
            mime = mime_map.get(ext, "application/octet-stream")
            try:
                with open(img_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_error(500, str(e))
            return

        api_routes = {
            "/api/news": lambda: get_news(date),
            "/api/rss": lambda: get_rss(date),
            "/api/stats": lambda: get_stats(date),
            "/api/tags": lambda: get_ai_tags(date),
            "/api/ai-results": lambda: get_ai_results(date),
            "/api/ai-filtered": lambda: get_ai_filtered(date),
            "/api/ai-analysis": lambda: read_ai_analysis() or "",
            "/api/dates": get_available_dates,
            "/api/jobs": lambda: _running_jobs,
            "/api/analyses": lambda: list_analyses(),
            "/api/articles": lambda: list_articles(),
            "/api/templates": lambda: _get_templates(),
            "/api/analytics/summary": lambda: _analytics_summary(),
            "/api/analytics/articles": lambda: _analytics_articles(),
            "/api/analytics/competitors": lambda: _analytics_competitors(),
            "/api/competitors/timeline": lambda: _competitors_timeline(params),
            "/api/competitors/topic-stats": lambda: _competitors_topic_stats(params),
            "/api/competitors/cadence": lambda: _competitors_cadence(params),
            "/api/competitors/coverage": lambda: _competitors_coverage(),
            "/api/competitors/insights": lambda: _competitors_insights(),
            "/api/competitors/scan-status": lambda: _competitors_scan_status(),
            "/api/recommendations": lambda: _get_recommendations(),
            "/api/video/scripts": lambda: _list_video_scripts(),
            "/api/projects": lambda: _list_projects(params.get("stage", [""])[0]),
            "/api/engagement": lambda: _get_engagement(date, params.get("item_id", [None])[0]),
            "/api/topic-events": lambda: _get_topic_events(),
            "/api/topic-trends": lambda: _get_topic_trends(int(params.get("top", ["10"])[0])),
            "/api/topic-hits": lambda: _get_topic_hits(params.get("week", [None])[0]),
            "/api/system-health": lambda: _get_system_health(),
        }

        if path == "/api/job":
            job_id = params.get("id", [None])[0]
            if job_id and job_id in _running_jobs:
                self._json(_running_jobs[job_id])
            else:
                self._json({"error": "job not found"})
            return

        if path == "/api/analysis-detail":
            fpath = params.get("file", [None])[0]
            # 收紧：仅允许落在 content-data/analysis 子目录、且非危险扩展名
            if fpath and _is_safe_detail_path(fpath) and os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data = _reparse_failed_insights(data, fpath)
                self._json(data)
            else:
                self._json({"error": "file not found or access denied"})
            return

        if path == "/api/project":
            pid = params.get("id", [None])[0]
            if pid:
                proj = _get_project(int(pid))
                self._json(proj or {"error": "not found"})
            else:
                self._json({"error": "id required"})
            return

        if path == "/api/fetch-page-text":
            url = params.get("url", [None])[0]
            if not url:
                self._json({"error": "url required"})
                return
            if _is_private_or_invalid_url(url):
                self._json({"error": "url not allowed"})
                return
            # Check cache first
            cached = _get_cached_page_texts([url])
            if url in cached:
                self._json({"text": cached[url]["text"], "url": url, "status": cached[url]["status"], "cached": True})
                return
            # Fetch and cache
            result = _fetch_and_cache_page_text(url)
            self._json({"text": result["text"], "url": url, "status": result["status"]})
            return

        if path == "/api/article-detail":
            fpath = params.get("file", [None])[0]
            # 收紧：仅允许落在 content-data/articles 子目录、且非危险扩展名
            if fpath and _is_safe_detail_path(fpath) and os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    self._json({"content": f.read(), "file": fpath})
            else:
                self._json({"error": "file not found or access denied"})
            return

        if path in api_routes:
            data = api_routes[path]()
            self._json(data)
        elif path == "/favicon.svg":
            fav = os.path.join(DASHBOARD_DIR, "favicon.svg")
            if os.path.exists(fav):
                with open(fav, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", len(body))
                self.send_header("Cache-Control", "public, max-age=86400")
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send_error_json(404, "not found")
        elif path == "/" or path == "/index.html":
            # 用白名单方式只服务 index.html，杜绝 /server.py /start.sh /Dockerfile 等源码暴露
            # 同时做模板替换，注入 Sentry frontend config（Stage 2.6）
            index_path = os.path.join(DASHBOARD_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "r", encoding="utf-8") as f:
                    text = f.read()
                # 模板变量替换
                _sentry_fe_dsn = os.environ.get("SENTRY_FRONTEND_DSN", "")
                text = text.replace("__SENTRY_FRONTEND_DSN__", _sentry_fe_dsn)
                text = text.replace("__SENTRY_ENVIRONMENT__", _SENTRY_ENV)
                text = text.replace("__SENTRY_RELEASE__", _SENTRY_RELEASE)
                body = text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-cache")
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send_error_json(500, "index.html missing")
        elif path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(body)
        elif path == "/healthz":
            # 健康检查：DB ping + LLM 配置 + 上线时长。不需要鉴权（探活）
            uptime = int(time.time() - _system_health.get("server_start_time", time.time()))
            health = {"status": "ok", "uptime_seconds": uptime}
            try:
                _c = _workflow_conn()
                _c.execute("SELECT 1").fetchone()
                _c.close()
                health["db"] = "ok"
            except Exception:
                health["status"] = "degraded"
                health["db"] = "error"
            has_llm = any(os.environ.get(k) for k in (
                "DEEPSEEK_API_KEY", "GEMINI_API_KEY", "TOKENKEY_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AIROUTER_API_KEY",
            ))
            health["llm"] = "ok" if has_llm else "missing"
            if health["llm"] == "missing":
                health["status"] = "degraded"
            health["auth_configured"] = _AUTH_CONFIGURED
            health["console_password_set"] = bool(_CONSOLE_PASSWORD)
            body = json.dumps(health).encode("utf-8")
            self.send_response(200 if health["status"] == "ok" else 503)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(body)
        else:
            # 默认：拒绝。绝不再 fallthrough 到 SimpleHTTPRequestHandler.do_GET（会暴露目录所有文件）
            self._send_error_json(404, "not found")

    def _json(self, data):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def _do_topic_scan():
    """Run a single topic scan. Auto-confirms high-value topics for analysis."""
    global _system_health
    try:
        from article.topic_detector import scan_and_recommend
        results = scan_and_recommend()
        print(f"[Topic Scan] Found {len(results)} recommended topics")
        _system_health["last_scan_time"] = time.time()
        _system_health["last_scan_result"] = "success"
        _system_health["last_scan_topics"] = len(results)
        # Detect eval method from results
        if results:
            # Check if LLM provided angle suggestions (non-rule-based)
            has_llm_angles = any(
                r.get("angle_suggestion", "") and "规则评估" not in r.get("angle_suggestion", "")
                for r in results
            )
            if has_llm_angles:
                _system_health["eval_method"] = "llm"
            else:
                wvs = set(r.get("write_value", 5) for r in results)
                _system_health["eval_method"] = "rule_fallback" if len(wvs) > 1 else "default_only"

        # 高价值话题 → 加入待审批队列（不再自动启动写作）
        # 条件：write_value >= 8 且 hot_score >= 50
        pending_added = 0
        for rec in results:
            wv = rec.get("write_value", 0)
            hs = rec.get("hot_score", 0)
            topic = rec.get("topic_title", "")
            if wv >= 8 and hs >= 50 and topic and topic not in _skipped_topics:
                # 检查是否已有此话题的项目
                conn = _workflow_conn()
                existing = conn.execute(
                    "SELECT id FROM projects WHERE topic LIKE ? LIMIT 1",
                    (f"%{topic[:30]}%",)
                ).fetchone()
                conn.close()
                if existing:
                    continue
                # 检查是否已在运行中
                already_running = any(
                    j.get("topic", "") == topic and j.get("status") == "running"
                    for j in _running_jobs.values()
                )
                if already_running:
                    continue
                # 加入待审批队列（不自动写作）
                if topic not in _pending_approvals:
                    _pending_approvals[topic] = {
                        "topic": topic,
                        "write_value": wv,
                        "hot_score": hs,
                        "added_time": time.strftime("%Y-%m-%d %H:%M"),
                    }
                    pending_added += 1
                    print(f"[Pending] Topic queued for approval: {topic[:50]} (wv={wv}, hs={hs:.0f})")
                    _send_feishu_notification(
                        f"📋 选题待审批: {topic[:40]}",
                        f"写作价值: {wv}/10 · 热度: {hs:.0f}\n请到 Dashboard 确认或跳过"
                    )
                    if pending_added >= 3:
                        break
        if pending_added:
            print(f"[Topic Scan] {pending_added} topics queued for approval")
    except Exception as e:
        _system_health["last_scan_time"] = time.time()
        _system_health["last_scan_result"] = f"error: {str(e)[:100]}"
        print(f"[Topic Scan] Error: {e}")


def _do_engagement_snapshot():
    """Generate engagement snapshots from current rank data.

    Since we don't have real engagement APIs for each platform,
    we convert rank position into a composite heat score:
    - rank 1 = 100 points, rank 2 = 95, rank 3 = 90, etc.
    - Cross-platform presence multiplier
    - Time on list bonus

    Runs every 30 minutes to build time-series data.
    """
    today = datetime.now().strftime("%Y-%m-%d")
    # 直接拼当天路径，不走 get_db_path 的"最新文件"fallback——
    # 否则当天没采集时会把快照写进旧日期的 db，导致旧文件无限膨胀
    db_path = os.path.join(DATA_DIR, "news", f"{today}.db")
    if not os.path.exists(db_path):
        return
    _ensure_engagement_table(db_path)
    now_str = datetime.now().strftime("%H-%M")

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Get all items with their current best rank and crawl count
        items = conn.execute("""
            SELECT n.id, n.platform_id, n.rank, n.crawl_count,
                   (SELECT MIN(r.rank) FROM rank_history r WHERE r.news_item_id = n.id) as best_rank
            FROM news_items n
            WHERE n.rank <= 30
        """).fetchall()

        # Check if we already have a snapshot within last 20 minutes
        recent = conn.execute("""
            SELECT COUNT(*) as c FROM engagement_snapshots
            WHERE snapshot_time > ?
        """, (datetime.now().strftime("%H-%M") if False else
              (datetime.now() - timedelta(minutes=20)).strftime("%H-%M"),)).fetchone()

        # Simple dedup: skip if last snapshot was less than 20 min ago
        last_snap = conn.execute("""
            SELECT snapshot_time FROM engagement_snapshots
            ORDER BY id DESC LIMIT 1
        """).fetchone()
        if last_snap:
            # Parse HH-MM format
            parts = last_snap["snapshot_time"].split("-")
            if len(parts) == 2:
                last_h, last_m = int(parts[0]), int(parts[1])
                now_h, now_m = datetime.now().hour, datetime.now().minute
                diff = (now_h * 60 + now_m) - (last_h * 60 + last_m)
                if 0 < diff < 20:
                    conn.close()
                    return

        inserted = 0
        for item in items:
            rank = item["rank"]
            crawl_count = item["crawl_count"] or 1
            best_rank = item["best_rank"] or rank

            # Compute heat score as "views" proxy
            # Base: position score (rank 1=100, rank 30=5)
            position_score = max(5, 100 - (rank - 1) * 3.2)
            # Persistence bonus: stayed on list longer = hotter
            persistence_bonus = min(30, crawl_count * 2.5)
            # Peak bonus: if it was #1 at some point
            peak_bonus = max(0, 20 - best_rank * 2) if best_rank <= 10 else 0

            heat_score = int(position_score + persistence_bonus + peak_bonus)

            conn.execute("""
                INSERT INTO engagement_snapshots (news_item_id, views, likes, comments, shares, snapshot_time)
                VALUES (?, ?, 0, 0, 0, ?)
            """, (item["id"], heat_score, now_str))
            inserted += 1

        conn.commit()
        conn.close()
        if inserted:
            print(f"[Engagement] Snapshot saved: {inserted} items at {now_str}")
    except Exception as e:
        print(f"[Engagement] Error: {e}")


def _do_topic_hit_analysis():
    """Analyze which hot events we covered with our articles/analyses.

    Compares topic_events with our projects to compute hit rate.
    """
    try:
        conn = sqlite3.connect(WORKFLOW_DB)
        conn.row_factory = sqlite3.Row

        # 获取所有热点事件
        events = conn.execute(
            "SELECT id, event_name, event_key, total_articles, lifecycle_stage FROM topic_events"
        ).fetchall()
        if not events:
            conn.close()
            return

        # 获取我们的项目
        projects = conn.execute(
            "SELECT id, topic, stage FROM projects"
        ).fetchall()

        # 获取已有的 hit 记录（避免重复）
        existing_hits = set()
        for h in conn.execute("SELECT event_id FROM our_topic_hits").fetchall():
            existing_hits.add(h[0])

        today = datetime.now()
        week_start = (today - timedelta(days=today.weekday())).strftime("%Y-%m-%d")

        for ev in events:
            if ev['id'] in existing_hits:
                continue

            event_key = ev['event_key'] or ''
            entities = set(event_key.split('+'))

            # 检查我们的项目是否覆盖了这个事件
            our_match = None
            for proj in projects:
                proj_topic = (proj['topic'] or '').lower()
                matched = sum(1 for ent in entities if ent.lower() in proj_topic)
                if matched >= len(entities) * 0.5 and matched > 0:
                    our_match = proj
                    break

            total_articles = ev['total_articles'] or 1
            if our_match:
                # 我们覆盖了
                share = min(1.0, 1.0 / total_articles)
                if our_match['stage'] in ('published', 'ready'):
                    verdict = '爆了' if total_articles >= 5 else '抓住了'
                elif our_match['stage'] in ('writing', 'review', 'human_review'):
                    verdict = '在写'
                else:
                    verdict = '有分析'
            else:
                share = 0
                verdict = '没抓住' if total_articles >= 3 else '未覆盖'

            conn.execute("""
                INSERT INTO our_topic_hits (event_id, our_views, total_event_views, share_pct, verdict, week_start)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ev['id'], 1 if our_match else 0, total_articles, round(share, 4), verdict, week_start))

        conn.commit()
        conn.close()
        print(f"[Topic Hits] Analyzed {len(events)} events")
    except Exception as e:
        print(f"[Topic Hits] Error: {e}")
        # Stage 2: 移除完整堆栈打印，避免在日志中泄露内部文件路径


def _do_event_clustering():
    """Cluster AI-filtered news into topic events across recent days.

    Uses keyword extraction + fuzzy matching to group related articles.
    Runs every 30 minutes alongside topic scan.
    """
    import re

    def _extract_entities(title):
        """Extract key entities/keywords from a title for clustering."""
        t = title.lower()
        # 核心实体列表（产品名/公司名/人名）
        entities = set()
        entity_map = {
            'deepseek': 'DeepSeek', 'deep seek': 'DeepSeek',
            'openai': 'OpenAI', 'open ai': 'OpenAI',
            'claude': 'Claude', 'anthropic': 'Anthropic',
            'gpt-5': 'GPT-5', 'gpt5': 'GPT-5', 'gpt-4': 'GPT-4',
            'gemini': 'Gemini', 'google': 'Google', '谷歌': 'Google',
            '微软': 'Microsoft', 'microsoft': 'Microsoft',
            'meta': 'Meta', 'llama': 'Llama',
            '马斯克': 'Musk', 'musk': 'Musk', 'altman': 'Altman', '奥特曼': 'Altman',
            '黄仁勋': 'Huang', 'nvidia': 'NVIDIA', '英伟达': 'NVIDIA',
            'cursor': 'Cursor', 'codex': 'Codex',
            '华为': 'Huawei', '小米': 'Xiaomi',
            'agent': 'Agent', '智能体': 'Agent',
            'ai短剧': 'AI短剧', 'ai 短剧': 'AI短剧',
            '机器人': '机器人', 'robot': '机器人',
            '融资': '融资', '财报': '财报', '营收': '财报',
            'v4': 'V4', 'v3': 'V3',
        }
        for keyword, entity in entity_map.items():
            if keyword in t:
                entities.add(entity)
        return entities

    def _make_event_key(entities):
        """Create a stable event key from sorted entities."""
        if not entities:
            return None
        # 按重要性排序：产品/公司名优先
        primary = sorted(entities)[:3]  # 最多取3个主要实体
        return '+'.join(primary)

    try:
        recent_dates = _get_recent_dates(5)
        if not recent_dates:
            return

        # 收集所有 AI 精选文章
        all_articles = []
        for d in recent_dates:
            items = _get_ai_filtered_single(d)
            for item in items:
                entities = _extract_entities(item.get('title', ''))
                if entities:
                    all_articles.append({
                        'title': item['title'],
                        'source': item.get('platform_name', item.get('feed_name', '')),
                        'date': d,
                        'entities': entities,
                        'views': item.get('crawl_count', 1),
                        'url': item.get('url', ''),
                    })

        if not all_articles:
            return

        # 按 event_key 聚类
        clusters = {}
        for art in all_articles:
            key = _make_event_key(art['entities'])
            if not key:
                continue
            if key not in clusters:
                clusters[key] = {
                    'event_key': key,
                    'articles': [],
                    'dates': set(),
                    'entities': art['entities'].copy(),
                }
            clusters[key]['articles'].append(art)
            clusters[key]['dates'].add(art['date'])
            clusters[key]['entities'] |= art['entities']

        # 只保留有 >= 2 篇文章的事件（单篇不算事件）
        events = {k: v for k, v in clusters.items() if len(v['articles']) >= 2}

        if not events:
            print("[Event Cluster] No multi-article events found")
            return

        # 写入数据库
        conn = sqlite3.connect(WORKFLOW_DB)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for key, ev in events.items():
            dates_sorted = sorted(ev['dates'])
            event_name = ' × '.join(sorted(ev['entities'])[:3])
            total_articles = len(ev['articles'])

            # 判断生命周期阶段
            today = datetime.now().strftime("%Y-%m-%d")
            if dates_sorted[-1] == today:
                if len(dates_sorted) <= 1:
                    stage = 'emerging'
                elif total_articles >= 5:
                    stage = 'peak'
                else:
                    stage = 'growing'
            else:
                stage = 'declining'

            # Upsert event
            existing = conn.execute(
                "SELECT id, total_articles FROM topic_events WHERE event_key = ?", (key,)
            ).fetchone()

            if existing:
                event_id = existing[0]
                conn.execute("""
                    UPDATE topic_events SET
                        event_name = ?, lifecycle_stage = ?,
                        total_articles = ?, peak_date = ?,
                        end_date = ?, updated_at = ?
                    WHERE id = ?
                """, (event_name, stage, total_articles,
                      dates_sorted[-1] if stage == 'peak' else None,
                      dates_sorted[-1] if stage == 'declining' else None,
                      now, event_id))
            else:
                cur = conn.execute("""
                    INSERT INTO topic_events (event_name, event_key, start_date, lifecycle_stage,
                                             total_articles, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (event_name, key, dates_sorted[0], stage, total_articles, now, now))
                event_id = cur.lastrowid

            # Upsert articles
            for art in ev['articles']:
                exists = conn.execute(
                    "SELECT id FROM event_articles WHERE event_id = ? AND article_title = ? AND data_date = ?",
                    (event_id, art['title'], art['date'])
                ).fetchone()
                if not exists:
                    conn.execute("""
                        INSERT INTO event_articles (event_id, article_title, source, data_date, views, url)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (event_id, art['title'], art['source'], art['date'], art['views'], art['url']))

        conn.commit()
        conn.close()
        print(f"[Event Cluster] Clustered {len(all_articles)} articles into {len(events)} events")
    except Exception as e:
        print(f"[Event Cluster] Error: {e}")
        # Stage 2: 移除完整堆栈打印，避免在日志中泄露内部文件路径


def _get_system_health():
    """Return system health status for dashboard console."""
    import shutil
    # Check LLM API key configuration
    # The system uses AIROUTER_API_KEY for multi-model analysis and topic evaluation
    llm_status = {}
    airouter_key = os.environ.get("AIROUTER_API_KEY", "")
    airouter_base = os.environ.get("AIROUTER_API_BASE", "https://airouter.cloud/v1")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")

    llm_status["airouter"] = "configured" if airouter_key else "missing"
    llm_status["anthropic"] = "configured" if (anthropic_key and not anthropic_key.startswith("sk-ant-xxx")) else "missing"
    llm_status["openai"] = "configured" if (openai_key and not openai_key.startswith("sk-xxx")) else "missing"
    llm_status["airouter_base"] = airouter_base

    # Check config.yaml for keys
    config_path = os.path.join(CE_ROOT, "config.yaml")
    config_keys = {"anthropic": False, "openai": False}
    try:
        with open(config_path, "r") as f:
            content = f.read()
            if "sk-ant-" in content and "sk-ant-xxx" not in content:
                config_keys["anthropic"] = True
            if "sk-" in content and "sk-xxx" not in content and "sk-ant-" not in content:
                config_keys["openai"] = True
    except:
        pass

    if config_keys["anthropic"] and llm_status["anthropic"] == "missing":
        llm_status["anthropic"] = "in_config"
    if config_keys["openai"] and llm_status["openai"] == "missing":
        llm_status["openai"] = "in_config"

    # Uptime
    uptime_secs = time.time() - _system_health["server_start_time"]

    # Disk space
    disk = shutil.disk_usage(DATA_DIR)
    disk_free_gb = disk.free / (1024**3)

    return {
        "llm": llm_status,
        "scan": {
            "last_time": _system_health["last_scan_time"],
            "last_result": _system_health["last_scan_result"],
            "topics_found": _system_health["last_scan_topics"],
            "eval_method": _system_health["eval_method"],
            "interval_minutes": 30,
            "auto_confirmed_total": _system_health["auto_confirmed_total"],
        },
        "server": {
            "uptime_seconds": int(uptime_secs),
            "port": PORT,
            "pid": os.getpid(),
            "disk_free_gb": round(disk_free_gb, 1),
        },
        "feishu_configured": bool(FEISHU_WEBHOOK_URL),
    }


_last_competitor_scan = 0  # epoch timestamp of last competitor scan


def _do_competitor_scan():
    """Periodic competitor RSS scan + AI insight generation (every 3h)."""
    global _last_competitor_scan
    # Only scan every 3 hours to avoid hammering RSS feeds
    if time.time() - _last_competitor_scan < 10800:
        return
    try:
        from article.analytics import (scan_all_competitor_rss,
                                       generate_competitive_insights,
                                       seed_default_competitors)
        seed_default_competitors()
        results = scan_all_competitor_rss(limit_per=30)
        new_total = sum(r.get("new", 0) for r in results if "new" in r)
        print(f"[Competitor Scan] Scanned {len(results)} feeds, {new_total} new articles")
        if new_total > 0:
            insights = generate_competitive_insights()
            print(f"[Competitor Scan] Generated {len(insights)} insights")
        _last_competitor_scan = time.time()
    except Exception as e:
        print(f"[Competitor Scan] Error: {e}")
        _last_competitor_scan = time.time()  # Don't retry immediately on error


def _do_auto_brief(max_per_round: int = 60):
    """给今日 AI 精选中无摘要的条目自动批量生成 brief（deepseek，便宜快）。

    热搜源多数抓不到正文，AI 精选的"内容"主要靠摘要撑——采集后自动补摘要，
    用户打开列表即有内容，无需手动点"一键生成"。
    """
    if os.environ.get("AUTO_BRIEF_ENABLED", "1") != "1":
        return
    try:
        items = get_ai_filtered()  # 今日 AI 精选
        if not items:
            return
        titles = [it["title"] for it in items if it.get("title")]
        cached = _get_cached_briefs(titles)
        todo = [(it["title"], it.get("url", "")) for it in items
                if it.get("title") and it["title"] not in cached][:max_per_round]
        if not todo:
            return
        print(f"[Auto-Brief] 为 {len(todo)} 条 AI 精选生成摘要...")
        from concurrent.futures import ThreadPoolExecutor
        done = 0
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = [pool.submit(_generate_and_cache_brief, t, u) for t, u in todo]
            for f in futs:
                try:
                    if "brief" in f.result():
                        done += 1
                except Exception:
                    pass
        print(f"[Auto-Brief] 完成 {done}/{len(todo)} 条摘要")
    except Exception as e:
        print(f"[Auto-Brief] Error: {e}")


def _schedule_topic_scan():
    """Background periodic scan every 30 minutes."""
    global _topic_scan_timer
    _do_topic_scan()
    _do_engagement_snapshot()
    _do_event_clustering()
    _do_topic_hit_analysis()
    _do_competitor_scan()
    _do_auto_brief()
    _topic_scan_timer = threading.Timer(1800, _schedule_topic_scan)
    _topic_scan_timer.daemon = True
    _topic_scan_timer.start()


def _recover_stuck_analyses():
    """启动时把上次中断的"分析中"project 标记为失败。

    异步分析 job 在内存（_running_jobs），dashboard 重启即丢失。db 里残留的
    stage='analysis' 都是中断的孤儿——标 failed 让前端显示"可重新分析"，
    而不是永远转圈或凭空消失。
    """
    try:
        conn = _workflow_conn()
        now = datetime.now().isoformat()
        cur = conn.execute(
            "UPDATE projects SET stage='failed', updated_at=?, "
            "notes='服务重启导致分析中断，可点重新分析' WHERE stage='analysis'",
            (now,))
        n = cur.rowcount
        conn.commit()
        conn.close()
        if n:
            print(f"[Startup] 标记 {n} 个中断的分析为 failed（可重新分析）")
    except Exception as e:
        print(f"[Startup] recover stuck analyses error: {e}")


def main():
    _recover_stuck_analyses()
    threading.Thread(target=_schedule_topic_scan, daemon=True).start()
    server = HTTPServer(("0.0.0.0", PORT), DashboardHandler)
    print(f"AI Radar Dashboard running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        if _topic_scan_timer:
            _topic_scan_timer.cancel()
        server.server_close()


if __name__ == "__main__":
    main()
