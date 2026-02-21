# Phantom: AI-Powered CloudFormation Drift Analysis & Reconciliation

Phantom detects and intelligently reconciles drift in AWS CloudFormation stacks by leveraging Claude AI, CloudTrail data, and Datadog observability to determine whether console changes should be legitimized, reverted, or refactored.

## The Problem

In production environments, infrastructure often diverges from Infrastructure as Code (IaC) definitions. Engineers make emergency console changes to resolve incidents, bypassing version control. Over time, this drift accumulates silently, introducing:
- **Hidden costs** from over-provisioned resources
- **Security misconfigurations** that don't match policy
- **Architectural inconsistencies** nobody fully understands

## The Solution

Phantom bridges the gap between actual deployed infrastructure and IaC by:

1. **Detecting Drift**: Uses AWS CloudFormation drift detection to identify resources that differ from the safe-state template
2. **Gathering Context**: Collects:
   - CloudTrail events showing who changed what and when
   - The original safe-state CloudFormation template
   - Datadog observability data (logs, traces, metrics) from around the time of drift
   - Cost reference data for impact analysis
3. **AI Analysis**: Sends drift context to Claude (via Amazon Bedrock) to reason about *why* the change occurred and what should happen next
4. **Intelligent Recommendations**: Claude produces one of three reconciliation decisions:
   - **Legitimize**: Console change was correct; update IaC to match live state
   - **Revert**: Console change was harmful; generate PR to restore safe state
   - **Refactor**: Change was directionally correct but poorly executed; optimize it based on post-incident metrics
5. **Automated Remediation**: Produces a rectified CloudFormation template and creates GitHub PRs with recommendations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ AWS CloudFormation Stack (Production)                            │
└──────────────────┬──────────────────┬───────────────────────────┘
                   │                  │
        ┌──────────▼──────────┐   ┌───▼──────────────┐
        │ Lambda Handler      │   │ CloudTrail Events│
        │ (drift detection)   │   │ (who/when)       │
        └─┬────────────────┬──┘   └───────────────────┘
          │                │
          │ Drift Data +   │ CloudTrail Events
          │ CloudFormation │
          │                │
        ┌─▼────────────────▼──────────────────┐
        │ Phantom Analyzer                     │
        │ • Loads drift + IaC templates       │
        │ • Fetches Datadog observability     │
        │ • Constructs Claude prompt          │
        │ • Invokes Bedrock                   │
        └─┬────────────────────────────────────┘
          │
          │ Analysis Output (recommendations)
          │
        ┌─▼──────────────────────────────────┐     ┌──────────────┐
        │ Phantom Rectifier                   │────▶│ GitHub PR    │
        │ • Applies per-change decisions      │     │ (automated)  │
        │ • Produces rectified template       │     └──────────────┘
        │ • Generates cost delta              │
        └─────────────────────────────────────┘
                     │
                     │
         ┌───────────▼──────────────┐
         │ Datadog Integration      │
         │ • Drift metrics emitted  │
         │ • Dashboards populated   │
         │ • Alerts triggered       │
         └──────────────────────────┘
```

## Components

### `lambda_handler.py`
AWS Lambda function that serves as the drift detection entry point.

**Responsibilities:**
- Lists all stack resources
- Triggers CloudFormation drift detection
- Polls for completion
- Retrieves original deployed template
- Extracts drifted resources with property diffs
- Queries CloudTrail for events on drifted resources (last 24 hours by default)
- Returns comprehensive drift report for Claude analysis

**Environment Variables:**
- `STACK_NAME`: CloudFormation stack to monitor (default: `phantom-test-stack`)
- `CLOUDTRAIL_HOURS`: How far back to search CloudTrail (default: `24`)

### `analyzer.py`
Orchestrates AI-powered drift analysis using Claude on Amazon Bedrock.

**Responsibilities:**
- Loads structured drift data (CloudFormation diffs, safe-state template)
- Fetches cost-reference data for impact analysis
- Retrieves Datadog observability context (logs, metrics, events)
- Constructs a multi-part prompt for Claude with:
  - The drift details
  - Safe-state IaC for architectural context
  - Who changed what and when (CloudTrail)
  - Observability signals (Datadog)
  - Cost data
- Invokes Claude via Amazon Bedrock API
- Parses recommendations and outputs structured analysis report

**Environment Variables:**
- `BEDROCK_REGION`: AWS region for Bedrock (default: `AWS_DEFAULT_REGION`)
- `BEDROCK_MODEL_ID`: Claude model to use (e.g., `anthropic.claude-3-sonnet-20240229-v1:0`)

**Output:** `analysis-output.json` with per-change recommendations including:
- Decision (legitimize/revert/refactor)
- Confidence score
- Natural language reasoning
- Cost delta breakdown
- Severity classification (low/medium/high/critical)

### `rectifier.py`
Applies Claude's recommendations to produce a reconciled CloudFormation template.

**Responsibilities:**
- Reads analysis report, safe-state, and drifted templates
- For each recommended change:
  - `revert`: Apply safe-state value
  - `legitimize`: Apply drifted value
  - `refactor`: Apply Claude's optimized value
- Handles complex property paths:
  - Simple: `InstanceType`
  - List indexes: `SecurityGroupIngress[2]`
  - Tag maps: `Tags[ManagedBy]`
- Preserves CloudFormation intrinsic functions (`!Ref`, `!GetAtt`, `!Sub`, etc.)
- Outputs rectified YAML template

**Output:** `rectified-template.yaml` with all recommendations applied

### `handler.py`
CLI utility to validate and test Datadog integration.

**Usage:**
```bash
# Fetch observability data for all services (last 12 hours)
python3 handler.py

# Fetch data for a specific service
python3 handler.py <service-name>
```

**Fetches:**
- Logs via Datadog Logs API
- Traces via Datadog APM API
- Metrics via Datadog Metrics Query API
- Events and monitors via Datadog Events API

### `utils/datadog.py`
Datadog API client utilities.

**Functions:**
- `dd_search_logs()`: Query logs with time range filtering
- `dd_list_traces()`: List APM traces with service/time filtering
- `dd_query_metrics()`: Query metrics using Datadog query language
- `dd_list_events()`: Retrieve events and alerts
- `dd_get_monitors()`: List monitor definitions

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-org/phantom.git
cd phantom
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables:**
Create a `.env` file in the project root:
```env
# AWS Configuration
STACK_NAME=your-production-stack
CLOUDTRAIL_HOURS=24
BEDROCK_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
AWS_DEFAULT_REGION=us-east-1

# Datadog Configuration
DD_API_KEY=your-datadog-api-key
DD_APP_KEY=your-datadog-application-key
```

## Usage

### 1. Detect Drift & Gather Context
Deploy `lambda_handler.py` as an AWS Lambda function:
```bash
# Lambda will be triggered on a schedule or manually
# It returns drift data including CloudTrail events
```

### 2. Analyze Drift with AI
Run the analyzer to get Claude's recommendations:
```bash
python3 analyzer.py
```

This outputs `analysis-output.json` with per-change recommendations.

### 3. Reconcile Infrastructure
Generate a corrected CloudFormation template:
```bash
python3 rectifier.py
```

This outputs `rectified-template.yaml` ready to deploy or create a PR.

### 4. Validate Datadog Integration (Optional)
Test your Datadog setup:
```bash
python3 handler.py
# or for a specific service:
python3 handler.py my-service
```

## CloudFormation Templates

### Safe State Template
`dummy-data/safe-state-template.yaml` — The golden version stored in version control representing desired infrastructure.

### Drifted Template
`dummy-data/drifted-template.yml` — Current live state extracted from AWS, showing all console changes.

### CloudFormation Stack
`cloudformation/infrastructure_cft.json` — IaC definition of the Phantom system itself (Lambda, IAM roles, etc.).

## Example Workflow

1. **3 AM Production Incident**: Engineer makes console changes to scale up resources and fix a performance issue
2. **Morning Detection**: Phantom Lambda runs on schedule, detects the changes
3. **AI Analysis**: Claude receives:
   - What changed (metrics increased)
   - Who changed it (engineer ID from CloudTrail)
   - When it happened (timestamp)
   - Why it might have happened (Datadog shows performance spike around that time)
   - Cost impact (resources are 40% more expensive)
4. **Recommendation**: Claude might recommend: "**Refactor** — The engineer correctly identified the need to scale, but over-provisioned. Recommend using auto-scaling policies instead of manual sizing."
5. **Automated PR**: System creates a GitHub PR with:
   - Rectified template with auto-scaling rules
   - Notes on cost savings
   - Link to incident timeline
6. **Team Review & Merge**: Team reviews and merges, closing the loop from incident to permanent fix

## Reconciliation Decision Logic

| Scenario | Decision | Action |
|----------|----------|--------|
| Security group rules tightened after incident | **Legitimize** | Update IaC to include stricter rules |
| Instance type downgraded without authorization | **Revert** | Restore to approved instance type |
| Resources over-provisioned during incident | **Refactor** | Scale down with auto-scaling instead of static sizing |
| Experimental changes left in production | **Revert** | Remove non-production configuration |
| Optimized configuration discovered through incident | **Legitimize** | Commit the optimization to IaC |

## Datadog Integration

Phantom emits metrics and monitors for observability:

- **Custom Metrics:**
  - `phantom.drift.count` — Number of drifted resources
  - `phantom.drift.severity` — Severity score (1-10) of detected drift
  - `phantom.reconciliation.cost_delta` — Monthly cost impact

- **Dashboard**: Visualizes drift trends, severity distribution, and reconciliation patterns over time

- **Monitors**: Alerts when:
  - High-severity drift detected in production
  - Reconciliation confidence score is low
  - Resolution timeline exceeds SLA

## Cost Impact Analysis

Each recommendation includes:
- **Current Cost**: Monthly spend with drifted resources
- **Rectified Cost**: Projected spend after applying recommendation
- **Delta**: Dollar and percentage impact
- **Payback Period**: Time to recoup savings from any optimization effort

## Security Considerations

- All CloudTrail queries are scoped to specific resource IDs to avoid excessive logging
- Datadog API calls use organization API keys (never IAM credentials)
- Lambda execution role has minimal permissions (drift detection + CloudTrail read)
- Analysis results are encrypted at rest in S3 (if stored)
- No credentials are logged or included in PR comments

## Limitations & Future Work

- Currently supports CloudFormation only (Terraform support planned)
- CloudTrail lookback limited to events within past 90 days
- Bedrock API costs scale with stack size and template complexity
- Manual review recommended for critical production stacks before deployment

## Contributing

1. Create a feature branch
2. Add tests for new analysis logic
3. Update documentation
4. Submit PR with console change and reconciliation example

## License

[Your License]

## Support

For issues or questions:
- Check `docs/initial-doc.md` for architecture details
- Review analysis output in `analysis-output.json` for debugging
- Enable verbose logging in Lambda for troubleshooting
- Validate with `python3 handler.py` to test Datadog connectivity
