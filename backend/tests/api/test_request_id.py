"""Request-ID middleware tests."""

from __future__ import annotations

import re
import threading
import uuid

import pytest
from fastapi.testclient import TestClient

VALID_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


@pytest.mark.unit
def test_inbound_request_id_is_echoed(client: TestClient) -> None:
    response = client.get("/health/live", headers={"X-Request-ID": "abc-123"})
    assert response.headers["x-request-id"] == "abc-123"


@pytest.mark.unit
def test_missing_request_id_generates_uuid(client: TestClient) -> None:
    response = client.get("/health/live")
    request_id = response.headers["x-request-id"]
    assert VALID_ID_RE.fullmatch(request_id) is not None
    assert uuid.UUID(request_id) is not None


@pytest.mark.unit
def test_invalid_request_id_is_replaced(client: TestClient) -> None:
    response = client.get("/health/live", headers={"X-Request-ID": "bad!id"})
    request_id = response.headers["x-request-id"]
    assert request_id != "bad!id"
    assert VALID_ID_RE.fullmatch(request_id) is not None
    assert uuid.UUID(request_id) is not None


@pytest.mark.unit
def test_concurrent_requests_get_distinct_ids(client: TestClient) -> None:
    ids: list[str] = []
    lock = threading.Lock()

    def fetch() -> None:
        response = client.get("/health/live")
        with lock:
            ids.append(response.headers["x-request-id"])

    threads = [threading.Thread(target=fetch) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(ids) == 2
    assert len(set(ids)) == 2
