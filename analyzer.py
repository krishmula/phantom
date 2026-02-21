"""
Phantom Analyzer — AI Infrastructure Drift Analysis via Claude on Bedrock

Loads structured drift data (diff, safe-state IaC, drifted IaC, Datadog
observability context, cost reference), constructs an analysis prompt, invokes
Claude on Amazon Bedrock via botocore SigV4, and outputs structured
reconciliation recommendations per drift change.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

import botocore.session
import requests
import yaml
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).parent / ".env")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DUMMY_DATA_DIR = Path(__file__).parent / "dummy-data"
OUTPUT_FILE = Path(__file__).parent / "analysis-output.json"

BEDROCK_REGION = os.environ.get("BEDROCK_REGION", os.environ.get("AWS_DEFAULT_REGION"))

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID")
MAX_TOKENS = 8192
TEMPERATURE = 0.2  # low temperature for deterministic analysis
MAX_RETRIES = 2

BEDROCK_INVOKE_URL = (
    f"https://bedrock-runtime.{BEDROCK_REGION}.amazonaws.com"
    f"/model/{MODEL_ID}/invoke"
)


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------
def load_json(filename: str) -> dict:
    """Load a JSON file from dummy-data/."""
    path = DUMMY_DATA_DIR / filename
    with open(path) as f:
        return json.load(f)


def load_text(filename: str) -> str:
    """Load a text/YAML file from dummy-data/ as raw string."""
    path = DUMMY_DATA_DIR / filename
    with open(path) as f:
        return f.read()


def load_structured_diff() -> dict:
    return load_json("structured-diff.json")


def load_datadog_context() -> dict:
    return load_json("sample-datadog-context.json")


def load_cost_reference() -> dict:
    return load_json("cost-reference.json")


def load_safe_state_template() -> str:
    return load_text("safe-state-template.yaml")


def load_drifted_template() -> str:
    return load_text("drifted-template.yml")


# ---------------------------------------------------------------------------
# Prompt Construction
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are Phantom — an expert AI infrastructure analyst specializing in AWS \
CloudFormation drift detection, incident response analysis, and IaC \
reconciliation.

You are given five inputs:
1. A STRUCTURED DIFF describing every property-level change between the \
safe-state CloudFormation template (stored in version control) and the \
current live state extracted via AWS IaC Generator.
2. The SAFE-STATE TEMPLATE — the CloudFormation YAML that represents the \
approved, version-controlled infrastructure.
3. The DRIFTED TEMPLATE — the CloudFormation YAML representing what is \
actually deployed in AWS right now, and what was modified via AWS Console. \
4. DATADOG OBSERVABILITY CONTEXT — alerts, metrics, traces, logs, and \
incident timeline from around the time the drift occurred.
5. A COST REFERENCE — AWS pricing data for computing cost deltas.

Your job is to analyze EACH individual drift change and produce a \
reconciliation recommendation. For every change you MUST decide one of:
- **legitimize**: The console change was correct and justified by the \
incident. Generate guidance to update the IaC repo to match the live state.
- **revert**: The change was unnecessary, harmful, or accidental. Generate \
guidance to restore the safe state.
- **refactor**: The change was directionally correct (e.g., scaling up was \
needed) but poorly executed (e.g., over-provisioned). Recommend an optimized \
middle-ground value based on actual post-incident metrics.

For each change provide:
- A confidence score (0.0–1.0)
- A severity classification (low / medium / high / critical)
- Natural language reasoning that references the Datadog context
- The monthly cost delta in USD (positive = more expensive, negative = savings, 0 for non-cost changes)
- If recommendation is "refactor", the suggested refactored_value

You MUST respond with ONLY valid JSON matching the schema below. No markdown \
fences, no commentary outside the JSON.

OUTPUT JSON SCHEMA:
{
  "stack_name": "<string>",
  "analysis_timestamp": "<ISO 8601>",
  "changes": [
    {
      "change_id": "<matches input change_id>",
      "resource_type": "<string>",
      "resource_logical_id": "<string>",
      "property_path": "<string>",
      "old_value": "<any>",
      "new_value": "<any>",
      "recommendation": "legitimize | revert | refactor",
      "confidence": <float 0-1>,
      "severity": "low | medium | high | critical",
      "reasoning": "<string — 2-4 sentences referencing incident/metrics>",
      "cost_delta_monthly_usd": <float>,
      "refactored_value": "<any, only if recommendation is refactor, else null>"
    }
  ],
  "aggregate_cost_delta": {
    "monthly_usd": <float>,
    "annualized_usd": <float>
  },
  "overall_severity": "low | medium | high | critical",
  "executive_summary": "<string — 2-3 sentences for engineering leadership>"
}\
"""


def build_user_message(
    diff: dict,
    safe_state: str,
    drifted_state: str,
    datadog_context: dict,
    cost_reference: dict,
) -> str:
    """Assemble the user message with all five data sources clearly delimited."""
    sections = []

    sections.append("=== STRUCTURED DIFF ===\n" + json.dumps(diff, indent=2))
    sections.append(
        "=== SAFE-STATE TEMPLATE (version-controlled IaC) ===\n" + safe_state
    )
    sections.append("=== DRIFTED TEMPLATE (live AWS state) ===\n" + drifted_state)
    sections.append(
        "=== DATADOG OBSERVABILITY CONTEXT ===\n"
        + json.dumps(datadog_context, indent=2)
    )
    sections.append(
        "=== COST REFERENCE (AWS pricing) ===\n" + json.dumps(cost_reference, indent=2)
    )

    sections.append(
        "Analyze every change in the structured diff. Produce the JSON reconciliation report now."
    )

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Bedrock Invocation
# ---------------------------------------------------------------------------
def _build_request_body(system_prompt: str, user_message: str) -> str:
    """Build the Anthropic Messages API request body for Bedrock."""
    return json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": MAX_TOKENS,
            "temperature": TEMPERATURE,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }
    )


def invoke_claude(system_prompt: str, user_message: str) -> str:
    """
    Call Claude on Bedrock using the Messages API via botocore SigV4.
    Returns the raw text content from Claude's response.
    """
    body = _build_request_body(system_prompt, user_message)

    # Set up SigV4 credentials
    session = botocore.session.get_session()
    credentials = session.get_credentials().get_frozen_credentials()

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(
                f"  → Invoking Bedrock via SigV4 (attempt {attempt}/{MAX_RETRIES})..."
            )
            t0 = time.time()

            # Sign the request with SigV4
            aws_request = AWSRequest(
                method="POST",
                url=BEDROCK_INVOKE_URL,
                data=body,
                headers={"content-type": "application/json", "accept": "*/*"},
            )
            SigV4Auth(credentials, "bedrock", BEDROCK_REGION).add_auth(aws_request)

            resp = requests.post(
                BEDROCK_INVOKE_URL,
                headers=dict(aws_request.headers),
                data=body,
                timeout=120,
            )
            resp.raise_for_status()
            result = resp.json()

            elapsed = time.time() - t0
            text = result["content"][0]["text"]

            # Log usage stats
            usage = result.get("usage", {})
            print(f"  ✓ Response received in {elapsed:.1f}s")
            print(
                f"    Tokens — input: {usage.get('input_tokens', '?')}, "
                f"output: {usage.get('output_tokens', '?')}"
            )
            return text

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            if status in (429, 503):
                last_error = e
                wait = 2**attempt
                print(f"  ⚠ HTTP {status} — retrying in {wait}s...")
                time.sleep(wait)
            else:
                body_text = e.response.text[:500] if e.response is not None else "N/A"
                print(f"  ✗ HTTP {status}: {body_text}")
                raise
        except Exception as e:
            last_error = e
            if attempt < MAX_RETRIES:
                wait = 2**attempt
                print(f"  ⚠ Error ({e}) — retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise

    raise RuntimeError(
        f"Bedrock invocation failed after {MAX_RETRIES} attempts: {last_error}"
    )


# ---------------------------------------------------------------------------
# Response Parsing
# ---------------------------------------------------------------------------
def parse_analysis_response(raw: str) -> dict:
    """
    Extract and validate the JSON reconciliation report from Claude's response.
    Handles both raw JSON and markdown-fenced (```json ... ```) responses.
    """
    text = raw.strip()

    # Try to extract from markdown code fence if present
    fence_match = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"\n✗ Failed to parse Claude's response as JSON: {e}")
        print(f"  Raw response (first 500 chars):\n  {raw[:500]}")
        raise

    # Validate required top-level keys
    required_keys = [
        "stack_name",
        "changes",
        "aggregate_cost_delta",
        "overall_severity",
        "executive_summary",
    ]
    missing = [k for k in required_keys if k not in data]
    if missing:
        print(f"  ⚠ Warning: Missing keys in response: {missing}")

    # Validate each change has required fields
    change_keys = [
        "change_id",
        "recommendation",
        "confidence",
        "severity",
        "reasoning",
        "cost_delta_monthly_usd",
    ]
    for i, change in enumerate(data.get("changes", [])):
        missing_change = [k for k in change_keys if k not in change]
        if missing_change:
            print(f"  ⚠ Warning: Change {i} missing keys: {missing_change}")

    return data


# ---------------------------------------------------------------------------
# Pretty-Print Report
# ---------------------------------------------------------------------------
SEVERITY_ICONS = {
    "low": "🟢",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}
RECOMMENDATION_ICONS = {
    "legitimize": "✅",
    "revert": "⏪",
    "refactor": "🔧",
}


def print_report(report: dict) -> None:
    """Pretty-print the reconciliation report to stdout."""
    print("\n" + "=" * 72)
    print("  PHANTOM — Infrastructure Drift Reconciliation Report")
    print("=" * 72)

    severity = report.get("overall_severity", "unknown")
    icon = SEVERITY_ICONS.get(severity, "❓")
    print(f"\n  Stack:            {report.get('stack_name', 'N/A')}")
    print(f"  Overall Severity: {icon} {severity.upper()}")
    print(f"  Analyzed at:      {report.get('analysis_timestamp', 'N/A')}")

    # Aggregate cost
    cost = report.get("aggregate_cost_delta", {})
    monthly = cost.get("monthly_usd", 0)
    annual = cost.get("annualized_usd", 0)
    sign = "+" if monthly >= 0 else ""
    print(f"  Cost Impact:      {sign}${monthly:,.2f}/mo ({sign}${annual:,.2f}/yr)")

    print(f"\n  Executive Summary:")
    print(f"  {report.get('executive_summary', 'N/A')}")

    # Per-change details
    changes = report.get("changes", [])
    print(f"\n{'─' * 72}")
    print(f"  CHANGE-BY-CHANGE ANALYSIS ({len(changes)} items)")
    print(f"{'─' * 72}")

    for change in changes:
        cid = change.get("change_id", "?")
        rec = change.get("recommendation", "?")
        rec_icon = RECOMMENDATION_ICONS.get(rec, "❓")
        sev = change.get("severity", "?")
        sev_icon = SEVERITY_ICONS.get(sev, "❓")
        conf = change.get("confidence", 0)
        cost_d = change.get("cost_delta_monthly_usd", 0)
        resource = change.get("resource_logical_id", "?")
        prop = change.get("property_path", "?")

        print(f"\n  {cid}: {resource}.{prop}")
        print(f"    {sev_icon} Severity:       {sev.upper()}")
        print(f"    {rec_icon} Recommendation: {rec.upper()} (confidence: {conf:.0%})")
        if cost_d != 0:
            sign = "+" if cost_d >= 0 else ""
            print(f"    💰 Cost delta:     {sign}${cost_d:,.2f}/mo")

        old = change.get("old_value")
        new = change.get("new_value")
        print(f"    Old → New:         {old} → {new}")

        refactored = change.get("refactored_value")
        if refactored is not None:
            print(f"    🔧 Refactored to:  {refactored}")

        reasoning = change.get("reasoning", "")
        # Wrap reasoning nicely
        print(f"    Reasoning: {reasoning}")

    print(f"\n{'=' * 72}\n")


# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------
def run_analysis() -> dict:
    """Orchestrate the full Phantom analysis pipeline."""
    print("\n🔍 Phantom Analyzer — Starting drift analysis...\n")

    # 1. Load data
    print("1/4  Loading drift data...")
    diff = load_structured_diff()
    safe_state = load_safe_state_template()
    drifted_state = load_drifted_template()
    datadog_ctx = load_datadog_context()
    cost_ref = load_cost_reference()
    print(
        f"     ✓ Loaded {diff['summary']['total_changes']} changes across "
        f"{diff['summary']['resources_affected']} resources"
    )

    # 2. Build prompt
    print("\n2/4  Constructing analysis prompt...")
    user_message = build_user_message(
        diff, safe_state, drifted_state, datadog_ctx, cost_ref
    )
    print(f"     ✓ Prompt assembled ({len(user_message):,} chars)")

    # 3. Invoke Claude on Bedrock
    print(f"\n3/4  Invoking Claude on Bedrock ({MODEL_ID})...")
    raw_response = invoke_claude(SYSTEM_PROMPT, user_message)

    # 4. Parse and validate
    print("\n4/4  Parsing reconciliation report...")
    report = parse_analysis_response(raw_response)
    print(f"     ✓ Parsed {len(report.get('changes', []))} change recommendations")

    # Write output
    with open(OUTPUT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Full JSON report saved to: {OUTPUT_FILE}")

    # Pretty-print
    print_report(report)

    return report


if __name__ == "__main__":
    try:
        run_analysis()
    except KeyboardInterrupt:
        print("\n\nAborted.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Analysis failed: {e}")
        sys.exit(1)
