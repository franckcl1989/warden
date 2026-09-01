#!/bin/sh
# Warden 事件接收容器入口（SNMP Trap / Syslog -> 统一设备事件；ARCHITECTURE §3.4）
set -eu

check_secret() {
    f=$1
    [ -s "$f" ] || { echo "启动失败：Secret 文件缺失或为空：$f" >&2; exit 1; }
}

check_secret "${WARDEN_POSTGRES_DSN_FILE:-/run/secrets/postgres_dsn}"

# 注意：app.workers.ingest 由 M1 实现；骨架阶段缺失会明确失败，不得伪装成功
exec python -m app.workers.ingest
