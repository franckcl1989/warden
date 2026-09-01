#!/bin/sh
# Warden Worker 容器入口（调度/采集/操作/维护；ARCHITECTURE §3.3）
set -eu

check_secret() {
    f=$1
    [ -s "$f" ] || { echo "启动失败：Secret 文件缺失或为空：$f" >&2; exit 1; }
}

check_secret "${WARDEN_CREDENTIAL_MASTER_KEY_FILE:-/run/secrets/credential_master_key}"
check_secret "${WARDEN_FILE_MASTER_KEY_FILE:-/run/secrets/file_master_key}"
check_secret "${WARDEN_POSTGRES_DSN_FILE:-/run/secrets/postgres_dsn}"

# 注意：app.workers.run 由 M1 实现；骨架阶段缺失会明确失败，不得伪装成功
exec python -m app.workers.run
