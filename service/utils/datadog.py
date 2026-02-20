from typing import Optional

import os
import requests

DD_BASE = "https://api.datadoghq.com/api"


def _headers() -> dict:
    return {
        "DD-API-KEY": os.environ["DD_API_KEY"],
        "DD-APPLICATION-KEY": os.environ["DD_APP_KEY"],
        "Content-Type": "application/json",
    }


def dd_search_logs(query: str, time_from: str, time_to: str, limit: int = 50) -> dict:
    """Search / retrieve logs from Datadog.

    Args:
        query:     Datadog log query string, e.g. "service:auth status:error".
        time_from: ISO-8601 start time, e.g. "2026-02-20T00:00:00Z".
        time_to:   ISO-8601 end time.
        limit:     Max logs to return (default 50, max 1000).
    """
    payload = {
        "filter": {"query": query, "from": time_from, "to": time_to},
        "sort": "-timestamp",
        "page": {"limit": limit},
    }
    resp = requests.post(f"{DD_BASE}/v2/logs/events/search", headers=_headers(), json=payload)
    resp.raise_for_status()
    return resp.json()


def dd_list_traces(query: str, time_from: str, time_to: str, limit: int = 50) -> dict:
    """Search / retrieve APM traces (spans) from Datadog.

    Args:
        query:     Datadog trace query, e.g. "service:web-app resource_name:/api/users".
        time_from: ISO-8601 start time.
        time_to:   ISO-8601 end time.
        limit:     Max spans to return (default 50, max 1000).
    """
    payload = {
        "data": {
            "attributes": {
                "filter": {"query": query, "from": time_from, "to": time_to},
                "sort": "timestamp",
                "page": {"limit": limit},
            },
            "type": "search_request",
        }
    }
    resp = requests.post(f"{DD_BASE}/v2/spans/events/search", headers=_headers(), json=payload)
    if not resp.ok:
        raise RuntimeError(f"{resp.status_code}: {resp.text}")
    return resp.json()


def dd_query_metrics(query: str, from_ts: int, to_ts: int) -> dict:
    """Query timeseries metric data from Datadog.

    Args:
        query:   Metrics query, e.g. "avg:system.cpu.user{*}" or "avg:system.cpu.user{label:phantom}".
        from_ts: Unix epoch start (seconds).
        to_ts:   Unix epoch end (seconds).
    """
    resp = requests.get(
        f"{DD_BASE}/v1/query",
        headers=_headers(),
        params={"query": query, "from": from_ts, "to": to_ts},
    )
    resp.raise_for_status()
    return resp.json()


def dd_list_events(query: str, from_ts: int, to_ts: int) -> dict:
    """Fetch events from Datadog.

    Args:
        query:   Event query, e.g. "sources:phantom" or "tags:label:phantom".
        from_ts: Unix epoch start (seconds).
        to_ts:   Unix epoch end (seconds).
    """
    resp = requests.get(
        f"{DD_BASE}/v1/events",
        headers=_headers(),
        params={"start": from_ts, "end": to_ts, "tags": query},
    )
    resp.raise_for_status()
    return resp.json()


def dd_get_monitors(query: Optional[str] = None) -> list:
    """Fetch monitors (alerts) from Datadog, optionally filtered by query.

    Args:
        query: Filter string, e.g. "tag:label:phantom" or monitor name substring.
    """
    params = {}
    if query:
        params["query"] = query
    resp = requests.get(f"{DD_BASE}/v1/monitor", headers=_headers(), params=params)
    resp.raise_for_status()
    return resp.json()
