# Warden 应用镜像：api / worker / event-ingest / migrate 共用（docs/DEPLOYMENT.md §2）。
# 发布构建必须把 python 基础镜像与 uv 工具镜像固定为 digest 引用（DEPLOYMENT §10 无公网交付包）。
FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# 依赖锁定安装（不联网解析版本；uv.lock 是唯一依据）
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./

# 非 root 运行（SECURITY §11）；容器 rootfs 由 Compose 设为只读
RUN useradd --create-home --uid 1000 warden && chown -R warden:warden /app

USER warden
ENV HOME=/tmp

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
