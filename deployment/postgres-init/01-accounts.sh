#!/bin/sh
# 首次初始化：创建最小权限应用账号与迁移账号（docs/SECURITY.md §11）。
# 说明：brief 原列名为 01-accounts.sql，但 psql 初始化脚本无法读取 Secret 文件，
# 密码必须来自 /run/secrets/* 只读挂载，因此实现为 shell 脚本（幂等，可重复执行）。
#
# 密码来源：postgres_dsn / postgres_dsn_migrate 两个 DSN Secret 文件（应用与迁移账号各自的
# postgresql:// 连接串）。密码只允许 [A-Za-z0-9._-]，避免 URL 编码与 SQL 引号转义
# （约束与 deployment/README.md 一致）。秘密不出现在仓库、Compose 或日志中。
set -eu

extract_password() {
    # postgresql://user:password@host:port/db -> password
    sed -n -E 's#^[A-Za-z][A-Za-z0-9+.-]*://[^/:]*:([^@]*)@.*$#\1#p' "$1"
}

validate_password() {
    case "$1" in
        ""|*[!A-Za-z0-9._-]*) return 1 ;;
        *) return 0 ;;
    esac
}

app_pw=$(extract_password /run/secrets/postgres_dsn)
migrate_pw=$(extract_password /run/secrets/postgres_dsn_migrate)

if ! validate_password "$app_pw" || ! validate_password "$migrate_pw"; then
    echo "初始化失败：DSN Secret 文件中的密码为空或含不允许的字符（仅 [A-Za-z0-9._-]）。" >&2
    echo "请修正 /srv/warden/secrets/postgres_dsn 与 postgres_dsn_migrate 后重新初始化。" >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
DO \$do\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'warden_app') THEN
        CREATE ROLE warden_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '$app_pw';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'warden_migrate') THEN
        CREATE ROLE warden_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '$migrate_pw';
    END IF;
END
\$do\$;

GRANT CONNECT ON DATABASE $POSTGRES_DB TO warden_app, warden_migrate;
GRANT USAGE ON SCHEMA public TO warden_app;
GRANT CREATE, USAGE ON SCHEMA public TO warden_migrate;
-- 迁移 0008（保留清理权限模型）：warden_app 需要 schema CREATE 才能由维护循环
-- 预创建 metric_points 日分区（PG18：即使拥有分区父表也需要 schema CREATE），
-- 且 ALTER OWNER 要求新属主拥有 schema CREATE；
-- warden_migrate 需要 warden_app 成员资格才能把可清理表的所有权转移给
-- warden_app（PG18：非超级用户 ALTER OWNER 必须是新属主角色的成员）。
-- 本脚本先于 migrate 容器运行，因此 0008 在生产环境可确定性地生效。
GRANT CREATE ON SCHEMA public TO warden_app;
GRANT warden_app TO warden_migrate;
SQL
