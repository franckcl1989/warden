#!/bin/sh
# Warden API 容器入口（DEPLOYMENT §2：0.1.0 单进程，ARCHITECTURE §2 理由）
# 只读 Secret 文件由 Compose 从 /srv/warden/secrets 挂载；缺失时拒绝启动（DEPLOYMENT §5）。
set -eu

check_secret() {
    f=$1
    [ -s "$f" ] || { echo "启动失败：Secret 文件缺失或为空：$f（请先运行 warden preflight 并补齐 /srv/warden/secrets/）" >&2; exit 1; }
}

check_secret "${WARDEN_CREDENTIAL_MASTER_KEY_FILE:-/run/secrets/credential_master_key}"
check_secret "${WARDEN_FILE_MASTER_KEY_FILE:-/run/secrets/file_master_key}"
check_secret "${WARDEN_SESSION_SECRET_FILE:-/run/secrets/session_secret}"
check_secret "${WARDEN_CSRF_SECRET_FILE:-/run/secrets/csrf_secret}"
check_secret "${WARDEN_POSTGRES_DSN_FILE:-/run/secrets/postgres_dsn}"

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
