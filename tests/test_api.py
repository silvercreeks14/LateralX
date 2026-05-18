"""
Basic API smoke tests using the FastAPI TestClient.
These tests do not require a running server or a valid Anthropic API key.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

PLASO_CSV = """datetime,timestamp_desc,source,source_long,message,parser,display_name,tag,hostname,username
2024-03-15 08:00:00,Creation Time,EVT,Windows Event Log,Event ID: 4624 logon,winevt,Security.evtx,,HOST-01,alice
2024-03-15 08:01:00,Creation Time,EVT,Windows Event Log,certutil.exe download,winevt,Security.evtx,,HOST-01,alice
"""


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_upload_csv():
    response = client.post(
        "/api/upload",
        files={"file": ("test.csv", PLASO_CSV, "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["events_loaded"] == 2
    assert data["filename"] == "test.csv"


def test_summary_after_upload():
    # Upload first
    client.post(
        "/api/upload",
        files={"file": ("test.csv", PLASO_CSV, "text/csv")},
    )
    response = client.get("/api/events/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert "HOST-01" in data["hosts"]


def test_events_filter():
    client.post(
        "/api/upload",
        files={"file": ("test.csv", PLASO_CSV, "text/csv")},
    )
    response = client.get("/api/events?host=HOST-01")
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 2
    assert all(e["source_host"] == "HOST-01" for e in events)


def test_graph_endpoint():
    client.post(
        "/api/upload",
        files={"file": ("test.csv", PLASO_CSV, "text/csv")},
    )
    response = client.get("/api/graph")
    assert response.status_code == 200
    data = response.json()
    assert "elements" in data
    assert "nodes" in data["elements"]
