#!/usr/bin/env python3
"""launchd 采集入口：先加载 content-engine/.env（AI key），再运行 trendradar。

为什么不用 shell grep 读 .env：macOS TCC（com.apple.macl）会拦 launchd 下的
grep 访问该文件，但 Python 进程内 open() 可以（dashboard server.py 同款做法）。
"""
import os
import runpy
import sys

ENV_PATH = "/Users/Zhuanz/Documents/daima/content-engine/.env"

try:
    with open(ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
except OSError as e:
    print(f"[run_crawl] 无法读取 {ENV_PATH}: {e}", file=sys.stderr)

# trendradar 读 AI_API_KEY；.env 里的字段名是 DEEPSEEK_API_KEY
if not os.environ.get("AI_API_KEY") and os.environ.get("DEEPSEEK_API_KEY"):
    os.environ["AI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
runpy.run_module("trendradar", run_name="__main__")
