import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

STACK_NAME = os.environ.get("STACK_NAME", "phantom-test-stack")
CLOUDTRAIL_HOURS = int(os.environ.get("CLOUDTRAIL_HOURS", "24"))  # how far back to look

cfn_client = boto3.client("cloudformation")
cloudtrail_client = boto3.client("cloudtrail")


def lambda_handler(event, context):

    try:
        # ---------------------------------------------------------- #
        # 1. Get all physical resource IDs from the stack            #
        # ---------------------------------------------------------- #
        resources_resp = cfn_client.list_stack_resources(StackName=STACK_NAME)
        stack_resources = {
            r["LogicalResourceId"]: r.get("PhysicalResourceId", "")
            for r in resources_resp["StackResourceSummaries"]
        }

        print(f"Stack has {len(stack_resources)} resources")

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

        # ---------------------------------------------------------- #
        # 5. Pull CloudTrail events for drifted resources only        #
        # ---------------------------------------------------------- #
        drifted_physical_ids = {d["PhysicalId"] for d in drifted_resources}
        start_time = datetime.now(timezone.utc) - timedelta(hours=CLOUDTRAIL_HOURS)
        cloudtrail_events = []

        for physical_id in drifted_physical_ids:
            if not physical_id:  # skip if PhysicalId is empty
                continue
            try:
                resp = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "ResourceName", "AttributeValue": physical_id}
                    ],
                    StartTime=start_time,
                    EndTime=datetime.now(timezone.utc),
                    MaxResults=10,  # last 10 events per resource is enough
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
                cloudtrail_events.append(
                    {
                        "ResourceId": physical_id,
                        "error": str(ct_err),
                    }
                )

        # Chronological order so Bedrock sees the change timeline clearly
        cloudtrail_events.sort(key=lambda x: x.get("EventTime", ""))

        # ---------------------------------------------------------- #
        # 6. Return everything Bedrock needs                          #
        # ---------------------------------------------------------- #
        return _response(
            200,
            {
                "stack_name": STACK_NAME,
                "drift_status": status["StackDriftStatus"],
                "drift_count": len(drifted_resources),
                "drifted_resources": drifted_resources,  # expected vs actual diff
                "cloudtrail_events": cloudtrail_events,  # who changed what and when
                "original_template": template,  # the template to fix
            },
        )

    except Exception as e:
        print(f"EXCEPTION: {str(e)}")
        return _response(500, {"error": str(e)})


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }
