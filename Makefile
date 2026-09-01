# Warden 0.1.0 unified task entry (Linux / CI).
# On Windows use the equivalent entry: pwsh -File scripts/tasks.ps1 <target>

SHELL := /bin/bash
BACKEND := backend
FRONTEND := frontend
PY := uv run --project $(BACKEND) --directory $(BACKEND)

.PHONY: help install lint format typecheck test test-backend test-frontend \
	contracts contracts-check openapi migrations migrate db-up db-down \
	build-frontend dev-api dev-worker dev-ingest dev-frontend compose-up compose-down \
	matrix check-design check-hardware check all

help:
	@echo "Warden tasks: install lint format typecheck test contracts openapi matrix migrations compose-up check"

# Fixed generation timestamp shared with the CI drift check; the committed
# matrix must be regenerated with this exact value (see
# tests/hardware-certification/README.md).
MATRIX_GENERATED_AT := 2026-09-01T00:00:00Z

matrix:
	pwsh -File scripts/generate-hardware-matrix.ps1 -GeneratedAt $(MATRIX_GENERATED_AT)

install:
	uv sync --project $(BACKEND) --all-extras
	cd $(FRONTEND) && npm ci

lint:
	$(PY) ruff check
	cd $(FRONTEND) && npm run lint

format:
	$(PY) ruff format
	cd $(FRONTEND) && npm run format

typecheck:
	$(PY) mypy
	cd $(FRONTEND) && npm run typecheck

contracts:
	$(PY) python -m app.tools.codegen

contracts-check: contracts
	git diff --exit-code -- backend/app/generated frontend/src/api/generated || \
		(echo "Generated contract artifacts drifted; run 'make contracts' and commit." && exit 1)

openapi:
	$(PY) python -m app.tools.openapi_export

test-backend:
	$(PY) pytest -q

test-frontend:
	cd $(FRONTEND) && npm run test

test: test-backend test-frontend

migrate:
	$(PY) alembic upgrade head

migration:
	$(PY) alembic revision --autogenerate -m "migration"

compose-up:
	docker compose -f deployment/compose/compose.yaml up -d

compose-down:
	docker compose -f deployment/compose/compose.yaml down

dev-api:
	$(PY) uvicorn app.main:app --app-dir $(BACKEND) --reload

dev-worker:
	$(PY) python -m app.workers.run

dev-ingest:
	$(PY) python -m app.workers.ingest

dev-frontend:
	cd $(FRONTEND) && npm run dev

check-design:
	pwsh -File scripts/check-design.ps1

check-hardware:
	pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json

check: check-design contracts-check lint typecheck test
