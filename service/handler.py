from dotenv import load_dotenv

load_dotenv(".env")

import sys  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from utils.datadog import dd_search_logs, dd_list_traces, dd_query_metrics, dd_list_events, dd_get_monitors  # noqa: E402


def get_all_for_service(service: str = None, hours: int = 12, limit: int = 10) -> dict:
    """Fetch all observability data from the last N hours. If service is given, scope to it."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    iso_end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    iso_start = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    from_epoch = int(start.timestamp())
    to_epoch = int(now.timestamp())

    log_query = f"service:{service}" if service else "*"
    trace_query = f"service:{service}" if service else "*"
    metric_query = (f"avg:trace.http.request.duration{{service:{service}}}"
                    if service else "avg:trace.http.request.duration{*}")
    event_query = f"service:{service}" if service else "*"

    results = {}

    # Logs
    try:
        results["logs"] = dd_search_logs(log_query, iso_start, iso_end, limit)
    except Exception as e:
        results["logs"] = {"error": str(e)}

    # Traces
    try:
        results["traces"] = dd_list_traces(trace_query, iso_start, iso_end, limit)
    except Exception as e:
        results["traces"] = {"error": str(e)}

    # Metrics
    try:
        results["metrics"] = dd_query_metrics(metric_query, from_epoch, to_epoch)
    except Exception as e:
        results["metrics"] = {"error": str(e)}

    # Events
    try:
        results["events"] = dd_list_events(event_query, from_epoch, to_epoch)
    except Exception as e:
        results["events"] = {"error": str(e)}

    return results


def print_service_data(service: str, data: dict):
    """Pretty-print all observability data for a service."""
    label = service if service else "ALL SERVICES"
    print(f"\n{'='*50}")
    print(f"  Observability data for: {label}")
    print(f"{'='*50}")

    # Logs
    logs = data.get("logs", {})
    print(f"\n--- Logs ---")
    if "error" in logs:
        print(f"  Error: {logs['error']}")
    else:
        entries = logs.get("data", [])
        for entry in entries:
            attrs = entry.get("attributes", {})
            print(f"  [{attrs.get('timestamp')}] {attrs.get('message', '')}")
        if not entries:
            print("  (none)")

    # Traces
    traces = data.get("traces", {})
    print(f"\n--- Traces ---")
    if "error" in traces:
        print(f"  Error: {traces['error']}")
    else:
        spans = traces.get("data", [])
        for span in spans:
            attrs = span.get("attributes", {})
            print(f"  {attrs.get('resource_name', '')} - {attrs.get('duration')}ns")
        if not spans:
            print("  (none)")

    # Metrics
    metrics = data.get("metrics", {})
    print(f"\n--- Metrics ---")
    if "error" in metrics:
        print(f"  Error: {metrics['error']}")
    else:
        series_list = metrics.get("series", [])
        for s in series_list:
            pts = s.get("pointlist", [])
            print(f"  {s.get('metric')}: {len(pts)} data points")
        if not series_list:
            print("  (none)")

    # Events
    events = data.get("events", {})
    print(f"\n--- Events ---")
    if "error" in events:
        print(f"  Error: {events['error']}")
    else:
        evts = events.get("events", [])
        for evt in evts:
            print(f"  [{evt.get('date_happened')}] {evt.get('title', '')}")
        if not evts:
            print("  (none)")



if __name__ == "__main__":
    service = sys.argv[1] if len(sys.argv) > 1 else None
    data = get_all_for_service(service)
    print_service_data(service, data)
