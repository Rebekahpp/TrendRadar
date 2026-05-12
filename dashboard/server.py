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

_topic_scan_timer = None
_skipped_topics = set()
FEISHU_WEBHOOK_URL = os.environ.get("FEISHU_WEBHOOK_URL", "")

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
    return sqlite3.connect(WORKFLOW_DB)


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
    return strong_hit or False


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
        return _get_ai_filtered_single(date)

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
            _send_feishu_notification(
                f"✅ 分析完成: {topic}",
                f"**话题**: {topic}\n"
                f"**成功模型**: {rd.get('models_succeeded', 0)}/4\n"
                f"**总洞察数**: {rd.get('total_insights', 0)}\n"
                f"**共识观点**: {len(rd.get('consensus_points', []))} 个\n"
                f"**分歧观点**: {len(rd.get('disagreement_points', []))} 个\n\n"
                f"🔗 [查看详情](http://localhost:9090)",
            )
            # 自动进入写文章阶段（全自动 pipeline）
            if rd.get('total_insights', 0) >= 5:
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
            article_path = save_article(result)  # Uses default output dir

            _running_jobs[job_id] = {
                "status": "done", "type": "article", "topic": topic,
                "result": result, "file": article_path, "project_id": project_id,
            }
            _update_project(project_id, stage="writing", article_file=article_path,
                            article_title=result.get("title", ""))
            _add_project_event(project_id, "article_auto_generated",
                               f"自��生成文章: {result.get('title','')} ({result.get('word_count',0)}字)")

            # 自动启动审核
            _auto_review_article(article_path, project_id, topic)

        except Exception as e:
            _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic}
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
            revise_count = _count_project_events(project_id, "auto_revision_done")
            if verdict == "publish" and score >= 8.0:
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


def _get_recommendations():
    try:
        from article.topic_detector import get_cached_recommendations
        data = get_cached_recommendations()
        recs = data.get("recommendations", [])
        filtered = [r for r in recs if r.get("topic_title", "") not in _skipped_topics]
        data["recommendations"] = filtered
        data["count"] = len(filtered)
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


def list_analyses():
    """List saved analysis files, enriched with workflow stage."""
    if not os.path.isdir(ANALYSIS_STORE):
        return []
    files = glob.glob(os.path.join(ANALYSIS_STORE, "*.json"))
    # 过滤掉非 analysis 的辅助文件
    files = [
        f for f in files
        if not os.path.basename(f).startswith(("source_verification_", "article_picks", "today_suggestions"))
        and not f.endswith(".verification.json")
    ]
    conn = _workflow_conn()
    conn.row_factory = sqlite3.Row
    results = []
    for f in sorted(files, key=os.path.getmtime, reverse=True)[:20]:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # 必须有 model_results 才算真正的 analysis
            if not data.get("model_results"):
                continue
            total = data.get("total_insights", 0) or 0
            succeeded = data.get("models_succeeded", 0) or 0
            topic = data.get("topic", "")
            # 用 realpath 匹配，因为 analysis_file 可能有不同的相对路径写法
            real_f = os.path.realpath(f)
            proj = conn.execute(
                "SELECT id, stage FROM projects WHERE analysis_file = ? LIMIT 1", (f,)
            ).fetchone()
            if not proj:
                # 尝试 realpath 匹配：遍历所有 projects 的 analysis_file
                all_projs = conn.execute("SELECT id, stage, analysis_file FROM projects").fetchall()
                for p in all_projs:
                    if p["analysis_file"] and os.path.realpath(p["analysis_file"]) == real_f:
                        proj = p
                        break
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
        except Exception:
            pass
    conn.close()
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


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
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
        elif path == "/api/save-api-keys":
            self._save_api_keys(body)
        elif path == "/api/generate-brief":
            self._generate_brief(body)
        elif path == "/api/generate-briefs-batch":
            self._generate_briefs_batch(body)
        else:
            self.send_error(404)

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
            for it in to_generate:
                t = it.get("title", "")
                u = it.get("url", "")
                if not t:
                    continue
                r = _generate_and_cache_brief(t, u)
                done += 1
                if "brief" in r:
                    _running_jobs[job_id]["results"][t] = r["brief"]
                _running_jobs[job_id]["done"] = done
            _running_jobs[job_id]["status"] = "done"

        threading.Thread(target=run, daemon=True).start()
        self._json({
            "job_id": job_id, "status": "started",
            "total": len(to_generate), "already_cached": len(cached),
            "cached_briefs": cached,
        })

    def _start_analysis(self, body):
        """Start multi-model analysis in background thread."""
        topic = body.get("topic", "").strip()
        context = body.get("context", "")
        if not topic:
            self._json({"error": "topic is required"})
            return
        job_id = _launch_analysis_job(topic, context)
        self._json({"job_id": job_id, "status": "started", "topic": topic})

    def _start_article_gen(self, body):
        """Generate article from analysis results or selected insights."""
        selected_insights = body.get("selected_insights", [])
        topic = body.get("topic", "")
        analysis_file = body.get("analysis_file", "")
        project_id = body.get("project_id")

        if not selected_insights and not analysis_file:
            self._json({"error": "need selected_insights or analysis_file"})
            return

        job_id = f"article_{int(datetime.now().timestamp())}"
        _running_jobs[job_id] = {"status": "running", "type": "article", "topic": topic, "project_id": project_id}

        if project_id:
            _update_project(project_id, stage="writing")
            _add_project_event(project_id, "writing_started", f"基于 {len(selected_insights)} 个洞察开始写作")

        def run():
            try:
                from article.generator import generate_article, save_article
                if selected_insights:
                    analysis = {
                        "topic": topic,
                        "selected_insights": selected_insights,
                        "total_insights": len(selected_insights),
                    }
                else:
                    with open(analysis_file, "r", encoding="utf-8") as f:
                        analysis = json.load(f)
                article = generate_article(analysis)
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
                    _update_project(project_id, stage="review",
                                    article_file=filepath,
                                    article_title=article.get("title", ""))
                    _add_project_event(project_id, "article_done",
                                       f"文章完成: {article.get('title', '')}")
                _send_feishu_notification(
                    f"✍️ 文章生成完成: {topic}",
                    f"**话题**: {topic}\n"
                    f"**标题**: {article.get('title', '未知')}\n"
                    f"**字数**: {len(article.get('content', ''))}\n\n"
                    f"🔗 [查看详情](http://localhost:9090)",
                )
            except Exception as e:
                _running_jobs[job_id] = {"status": "error", "error": str(e), "topic": topic, "project_id": project_id}
                if project_id:
                    _add_project_event(project_id, "writing_failed", str(e)[:500])
                _send_feishu_notification(
                    f"❌ 文章生成失败: {topic}",
                    f"**话题**: {topic}\n**错误**: {str(e)[:200]}",
                )

        threading.Thread(target=run, daemon=True).start()
        self._json({"job_id": job_id, "status": "started", "topic": topic})

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
                        author=wechat_cfg.get("author", ""),
                        thumb_media_id=wechat_cfg.get("default_thumb_media_id", ""),
                        dry_run=dry_run,
                    )
                    if not dry_run and project_id:
                        _update_project(int(project_id), stage="published")
                        _add_project_event(int(project_id), "published",
                                           f"已发布到微信公众号: {result.get('article_url', '')}")
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
            self._json({"error": str(e)})

    def _load_wechat_config(self):
        """Load WeChat config from content-engine/config.yaml."""
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
            self._json({"error": str(e)})

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
            )
            self._json({"success": True, "competitor_id": cid})
        except Exception as e:
            self._json({"error": str(e)})

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
            self._json({"error": str(e)})

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
        job_id = _launch_analysis_job(topic, context)
        self._json({"job_id": job_id, "status": "started", "topic": topic})

    def _skip_recommendation(self, body):
        """Skip a recommended topic."""
        topic = body.get("topic", "").strip()
        if topic:
            _skipped_topics.add(topic)
        self._json({"success": True, "skipped": topic})

    def _set_feishu_webhook(self, body):
        global FEISHU_WEBHOOK_URL
        url = body.get("url", "").strip()
        FEISHU_WEBHOOK_URL = url
        self._json({"success": True, "url": url})

    def _test_feishu_webhook(self, body):
        _send_feishu_notification("🧪 测试通知", "AI Radar 通知已连通！\n分析完成后将自动推送到这里。")
        self._json({"success": True, "sent": bool(FEISHU_WEBHOOK_URL)})

    def _video_generate_script(self, body):
        topic = body.get("topic", "").strip()
        context = body.get("context", "")
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
        """Save API keys to .env file and update os.environ."""
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
            os.makedirs(os.path.dirname(env_path), exist_ok=True)
            with open(env_path, "w") as f:
                f.write("# Content Engine Environment Variables\n")
                f.write("# Auto-generated by Dashboard\n\n")
                for k, v in existing.items():
                    f.write(f'{k}="{v}"\n')
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
            self._json({"error": str(e)})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        date = params.get("date", [None])[0]

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
            "/api/recommendations": lambda: _get_recommendations(),
            "/api/video/scripts": lambda: _list_video_scripts(),
            "/api/projects": lambda: _list_projects(params.get("stage", [""])[0]),
            "/api/engagement": lambda: _get_engagement(date, params.get("item_id", [None])[0]),
            "/api/topic-events": lambda: _get_topic_events(),
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
            if fpath and os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data = _reparse_failed_insights(data, fpath)
                self._json(data)
            else:
                self._json({"error": "file not found"})
            return

        if path == "/api/project":
            pid = params.get("id", [None])[0]
            if pid:
                proj = _get_project(int(pid))
                self._json(proj or {"error": "not found"})
            else:
                self._json({"error": "id required"})
            return

        if path == "/api/article-detail":
            fpath = params.get("file", [None])[0]
            if fpath and os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    self._json({"content": f.read(), "file": fpath})
            else:
                self._json({"error": "file not found"})
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
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)
        elif path == "/" or path == "/index.html":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def _json(self, data):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
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

        # 自动确认高价值话题：write_value >= 8 且 hot_score >= 50
        # 避免重复：检查是否已有同名项目或正在分析
        auto_confirmed = 0
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
                # 自动启动分析
                job_id = _launch_analysis_job(topic, "")
                auto_confirmed += 1
                print(f"[Auto-Confirm] Topic: {topic[:50]} (wv={wv}, hs={hs:.0f}) -> job {job_id}")
                _send_feishu_notification(
                    f"🤖 自动选题: {topic[:40]}",
                    f"写作价值: {wv}/10 · 热度: {hs:.0f}\n已自动启动多模型分析"
                )
                if auto_confirmed >= 2:  # 每轮最多自动确认 2 个
                    break
        if auto_confirmed:
            _system_health["auto_confirmed_total"] += auto_confirmed
            print(f"[Topic Scan] Auto-confirmed {auto_confirmed} high-value topics")
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
    db_path = get_db_path("news", today)
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
        import traceback
        traceback.print_exc()


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
        import traceback
        traceback.print_exc()


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


def _schedule_topic_scan():
    """Background periodic scan every 30 minutes."""
    global _topic_scan_timer
    _do_topic_scan()
    _do_engagement_snapshot()
    _do_event_clustering()
    _do_topic_hit_analysis()
    _topic_scan_timer = threading.Timer(1800, _schedule_topic_scan)
    _topic_scan_timer.daemon = True
    _topic_scan_timer.start()


def main():
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
