import base64
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3

STACK_NAME = os.environ.get("STACK_NAME", "phantom-test-stack")
CLOUDTRAIL_HOURS = int(os.environ.get("CLOUDTRAIL_HOURS", "24"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")
GITHUB_REPO = os.environ.get("GITHUB_REPO")
GITHUB_FILE_PATH = os.environ.get("GITHUB_FILE_PATH", "drift-reports/latest.json")
GITHUB_BASE = os.environ.get("GITHUB_BASE_BRANCH", "main")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-sonnet-4-5")

cfn_client = boto3.client("cloudformation")
cloudtrail_client = boto3.client("cloudtrail")
bedrock_client = boto3.client("bedrock-runtime")


def lambda_handler(event, context):

    try:
        # ---------------------------------------------------------- #
        # 1. Get stack resources                                      #
        # ---------------------------------------------------------- #
        resources_resp = cfn_client.list_stack_resources(StackName=STACK_NAME)
        print(f"Stack has {len(resources_resp['StackResourceSummaries'])} resources")

        # ---------------------------------------------------------- #
        # 2. Run drift detection                                      #
        # ---------------------------------------------------------- #
        detection_id = cfn_client.detect_stack_drift(StackName=STACK_NAME)[
            "StackDriftDetectionId"
        ]

        print(f"Drift detection started: {detection_id}")

        while True:
            status = cfn_client.describe_stack_drift_detection_status(
                StackDriftDetectionId=detection_id
            )
            print(f"Detection status: {status['DetectionStatus']}")

            if status["DetectionStatus"] == "DETECTION_COMPLETE":
                break
            elif status["DetectionStatus"] == "DETECTION_FAILED":
                return _response(
                    500,
                    {
                        "error": "Drift detection failed",
                        "reason": status.get(
                            "DetectionStatusReason", "no reason returned"
                        ),
                    },
                )
            time.sleep(5)

        # ---------------------------------------------------------- #
        # 3. Get original deployed template                           #
        # ---------------------------------------------------------- #
        template = cfn_client.get_template(
            StackName=STACK_NAME, TemplateStage="Original"
        )["TemplateBody"]

        if isinstance(template, dict):
            template = json.dumps(template, indent=2)

        # ---------------------------------------------------------- #
        # 4. Get drifted resources                                    #
        # ---------------------------------------------------------- #
        drifts = cfn_client.describe_stack_resource_drifts(
            StackName=STACK_NAME,
            StackResourceDriftStatusFilters=["MODIFIED", "DELETED"],
        )["StackResourceDrifts"]

        drifted_resources = [
            {
                "LogicalId": d["LogicalResourceId"],
                "PhysicalId": d.get("PhysicalResourceId", ""),
                "ResourceType": d["ResourceType"],
                "DriftStatus": d["StackResourceDriftStatus"],
                "ExpectedProperties": json.loads(d.get("ExpectedProperties", "{}")),
                "ActualProperties": json.loads(d.get("ActualProperties", "{}")),
                "PropertyDiffs": d.get("PropertyDifferences", []),
            }
            for d in drifts
        ]

        # If nothing drifted, exit early
        if not drifted_resources:
            print("No drift detected — stack is in sync")
            return _response(
                200,
                {
                    "drift_status": "IN_SYNC",
                    "drift_count": 0,
                    "message": "Stack is in sync, no action needed",
                },
            )

        # ---------------------------------------------------------- #
        # 5. Pull CloudTrail events for drifted resources only        #
        # ---------------------------------------------------------- #
        drifted_physical_ids = {d["PhysicalId"] for d in drifted_resources}
        start_time = datetime.now(timezone.utc) - timedelta(hours=CLOUDTRAIL_HOURS)
        cloudtrail_events = []

        for physical_id in drifted_physical_ids:
            if not physical_id:
                continue
            try:
                resp = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "ResourceName", "AttributeValue": physical_id}
                    ],
                    StartTime=start_time,
                    EndTime=datetime.now(timezone.utc),
                    MaxResults=10,
                )
                for e in resp.get("Events", []):
                    cloudtrail_events.append(
                        {
                            "ResourceId": physical_id,
                            "EventName": e.get("EventName"),
                            "EventTime": str(e.get("EventTime")),
                            "Username": e.get("Username", "unknown"),
                            "EventSource": e.get("EventSource"),
                            "CloudTrailEvent": json.loads(
                                e.get("CloudTrailEvent", "{}")
                            ),
                        }
                    )
            except Exception as ct_err:
                print(f"CloudTrail lookup failed for {physical_id}: {ct_err}")

        cloudtrail_events.sort(key=lambda x: x.get("EventTime", ""))

        # ---------------------------------------------------------- #
        # 6. Send to Bedrock — generate corrected CFN template        #
        # ---------------------------------------------------------- #
        print(f"Sending drift context to Bedrock ({BEDROCK_MODEL_ID})...")
        corrected_template = _call_bedrock(
            template, drifted_resources, cloudtrail_events
        )
        print("Bedrock returned corrected template ✓")

        # ---------------------------------------------------------- #
        # 7. Build the drift report payload                           #
        # ---------------------------------------------------------- #
        drift_report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stack_name": STACK_NAME,
            "drift_status": status["StackDriftStatus"],
            "drift_count": len(drifted_resources),
            "drifted_resources": drifted_resources,
            "cloudtrail_events": cloudtrail_events,
            "original_template": json.loads(template)
            if isinstance(template, str)
            else template,
            "corrected_template": corrected_template,  # AI-generated fix
        }

        # ---------------------------------------------------------- #
        # 8. Push corrected template to GitHub as a PR                #
        # ---------------------------------------------------------- #
        pr_url = None
        if GITHUB_TOKEN and GITHUB_OWNER and GITHUB_REPO:
            pr_url = _open_github_pr(drift_report)
        else:
            print("GitHub env vars not set — skipping PR creation")

        return _response(
            200,
            {
                "drift_status": drift_report["drift_status"],
                "drift_count": drift_report["drift_count"],
                "pr_url": pr_url,
                "drift_report": drift_report,
            },
        )

    except Exception as e:
        print(f"EXCEPTION: {str(e)}")
        return _response(500, {"error": str(e)})


def _call_bedrock(original_template, drifted_resources, cloudtrail_events):
    """
    Sends the drift context to Claude on Bedrock.
    Returns a corrected CloudFormation template as a dict.
    """

    # Build a human-readable diff summary for the prompt
    diff_summary = []
    for r in drifted_resources:
        diff_summary.append(
            f"Resource: {r['LogicalId']} ({r['ResourceType']}) — {r['DriftStatus']}"
        )
        for diff in r.get("PropertyDiffs", []):
            diff_summary.append(
                f"  Path: {diff['PropertyPath']}\n"
                f"  Expected: {diff['ExpectedValue']}\n"
                f"  Actual:   {diff['ActualValue']}\n"
                f"  Change:   {diff['DifferenceType']}"
            )

    cloudtrail_summary = ""
    if cloudtrail_events:
        cloudtrail_summary = "\n".join(
            [
                f"- {e['EventTime']} | {e['Username']} | {e['EventName']}"
                for e in cloudtrail_events[:5]  # limit to last 5 events
            ]
        )
    else:
        cloudtrail_summary = "No CloudTrail events captured."

    prompt = f"""You are an AWS CloudFormation expert. A CloudFormation stack has drifted because someone made manual changes in the AWS Console.

Your job is to update the original CloudFormation template to reflect the actual live state of the resources.

## Original Deployed Template
```json
{original_template}
```

## Drift Detected
{chr(10).join(diff_summary)}

## CloudTrail Activity (who made the changes)
{cloudtrail_summary}

## Instructions
1. Update the original template to match the actual live state shown in the drift
2. Only modify the resources that have drifted — leave everything else exactly as-is
3. Return ONLY the corrected CloudFormation template as valid JSON
4. Do not include any explanation, markdown, or code fences — just the raw JSON template

Return the corrected CloudFormation template now:"""

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            }
        ),
    )

    response_body = json.loads(response["body"].read())
    raw_text = response_body["content"][0]["text"].strip()

    # Strip any accidental markdown fences Claude might add
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]

    return json.loads(raw_text.strip())


def _open_github_pr(drift_report):
    """
    Pushes the AI-corrected CFN template (not the drift report JSON)
    to a new branch and opens a PR.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"drift/{timestamp}"
    api_base = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.github.v3+json",
    }

    # Step 1 — get base branch SHA
    base_sha = _github_request(
        "GET", f"{api_base}/git/ref/heads/{GITHUB_BASE}", headers
    )["object"]["sha"]

    # Step 2 — create new branch
    _github_request(
        "POST",
        f"{api_base}/git/refs",
        headers,
        {
            "ref": f"refs/heads/{branch}",
            "sha": base_sha,
        },
    )
    print(f"Created branch: {branch}")

    # Step 3 — check if CFN template file already exists
    cfn_file_path = os.environ.get(
        "CFN_TEMPLATE_PATH", "cloudformation/infrastructure_cft.json"
    )
    file_sha = None
    try:
        existing = _github_request(
            "GET", f"{api_base}/contents/{cfn_file_path}?ref={GITHUB_BASE}", headers
        )
        file_sha = existing.get("sha")
    except Exception:
        pass

    # Step 4 — push the corrected template to the new branch
    corrected_content = json.dumps(drift_report["corrected_template"], indent=2)
    encoded = base64.b64encode(corrected_content.encode()).decode()

    drifted_names = [d["LogicalId"] for d in drift_report["drifted_resources"]]
    put_body = {
        "message": f"fix: reconcile drift in {', '.join(drifted_names)} [{timestamp}]",
        "content": encoded,
        "branch": branch,
    }
    if file_sha:
        put_body["sha"] = file_sha

    _github_request("PUT", f"{api_base}/contents/{cfn_file_path}", headers, put_body)
    print(f"Pushed corrected template to branch: {branch}")

    # Step 5 — open the PR with a rich description
    diffs_md = "\n".join(
        [
            f"- `{d['LogicalId']}` ({d['ResourceType']}) — **{d['DriftStatus']}**\n"
            + "\n".join(
                [
                    f"  - `{p['PropertyPath']}`: `{p['ExpectedValue']}` → `{p['ActualValue']}` ({p['DifferenceType']})"
                    for p in d.get("PropertyDiffs", [])
                ]
            )
            for d in drift_report["drifted_resources"]
        ]
    )

    pr = _github_request(
        "POST",
        f"{api_base}/pulls",
        headers,
        {
            "title": f"[Drift Fix] {drift_report['stack_name']} — {', '.join(drifted_names)}",
            "body": (
                f"## 🤖 AI-Generated IaC Drift Fix\n\n"
                f"**Stack:** `{drift_report['stack_name']}`\n"
                f"**Detected at:** {drift_report['generated_at']}\n"
                f"**Resources drifted:** {drift_report['drift_count']}\n\n"
                f"### What Changed\n{diffs_md}\n\n"
                f"### How This Was Fixed\n"
                f"Claude on Amazon Bedrock analyzed the drift diff and CloudTrail context, "
                f"then generated an updated CloudFormation template that reflects the actual live state.\n\n"
                f"> Merge this PR to redeploy the corrected template via GitHub Actions."
            ),
            "head": branch,
            "base": GITHUB_BASE,
        },
    )

    pr_url = pr["html_url"]
    print(f"PR opened: {pr_url}")
    return pr_url


def _github_request(method, url, headers, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise Exception(f"GitHub API error {e.code}: {e.read().decode()}")


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }
