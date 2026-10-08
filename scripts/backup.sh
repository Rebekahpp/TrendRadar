#!/usr/bin/env bash
# AI Radar daily backup script — Stage 2
# 用法：
#   1. Coolify 里挂一个备份卷到 /backup
#   2. 在 host 上 cron：0 3 * * * docker exec ai-radar /app/scripts/backup.sh
#      或在外部 host 上：rsync from container volumes to a remote
#   3. 备份保留 14 天

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backup}"
DATA_ROOT="${DATA_ROOT:-/data}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
DATE=$(date +%Y%m%d_%H%M%S)
ARCHIVE="$BACKUP_DIR/ai-radar-$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "[backup] target=$ARCHIVE"

# 1. WAL checkpoint：确保所有写入合并入主库文件，避免备份得到不一致的 -wal/-shm
if [ -f "$DATA_ROOT/content-data/workflow.db" ]; then
  python3 - <<'PY' || true
import sqlite3, os
for p in ("/data/content-data/workflow.db",):
    if os.path.exists(p):
        try:
            c = sqlite3.connect(p, timeout=15)
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            c.close()
            print(f"[backup] wal_checkpoint ok: {p}")
        except Exception as e:
            print(f"[backup] wal_checkpoint failed: {e}")
PY
fi

# 2. 打包 content-data + output（排除超大模型/缓存）
tar -czf "$ARCHIVE" \
  --exclude='*.tmp' \
  --exclude='*-wal' \
  --exclude='*-shm' \
  -C "$DATA_ROOT" content-data output 2>/dev/null || {
    echo "[backup] tar failed"
    exit 1
  }

SIZE=$(du -h "$ARCHIVE" | cut -f1)
echo "[backup] done: $ARCHIVE ($SIZE)"

# 3. 清理旧备份
find "$BACKUP_DIR" -name 'ai-radar-*.tar.gz' -mtime +$RETENTION_DAYS -delete
echo "[backup] cleaned files older than $RETENTION_DAYS days"

# 4. 可选：上传到 S3 / R2 / OSS
# aws s3 cp "$ARCHIVE" "s3://my-bucket/ai-radar/$(basename $ARCHIVE)" --storage-class STANDARD_IA
