#!/bin/sh
# 一次性迁移容器入口（DATA_MODEL §12：独立 migrate 容器执行 Alembic，API 不抢跑）
# 使用独立 warden_migrate 账号（SECURITY §11）；DSN 由 WARDEN_POSTGRES_DSN_FILE 指向。
set -eu

f=${WARDEN_POSTGRES_DSN_FILE:-/run/secrets/postgres_dsn_migrate}
[ -s "$f" ] || { echo "启动失败：迁移账号 DSN Secret 文件缺失或为空：$f" >&2; exit 1; }

exec alembic upgrade head
