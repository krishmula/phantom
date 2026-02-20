### Phantom

In organizations, infrastructure is managed through Infrastructure as Code — CloudFormation templates and Terraform configs stored in version-controlled repositories representing the "safe state" of the system. But during incidents and firefighting, engineers often bypass this process entirely, making changes directly through the AWS console to resolve production issues under pressure. These console changes create drift between what's actually running in AWS and what the IaC repo says should be running. Over time, this drift accumulates silently, introducing hidden costs, security misconfigurations, and architectural inconsistencies that nobody fully understands or owns.
The project uses AWS's IaC Generator to extract the current CloudFormation representation of what's actually deployed in AWS — including any changes made through the console — and diffs it against the safe state CloudFormation stored in the team's GitHub repository. But instead of just showing a raw diff, we feed three things into Claude (Sonnet/Opus via the Anthropic API): the diff itself, the safe state IaC for architectural context, and Datadog observability data from around the time the drift occurred — alerts that fired, metrics spikes, incident timelines, service health signals. Using this combined context, Claude acts as an AI infrastructure analyst that doesn't just detect what changed, but reasons about why it changed and what should happen next. It produces one of three reconciliation recommendations: legitimize (the console change was correct, generate a PR to update the repo to match the live state), revert (the change was unnecessary or harmful, generate a PR to restore the safe state), or refactor (the change was directionally correct but poorly executed — for example, an engineer over-provisioned during a panic — so generate a PR with an optimized version based on actual post-incident metrics). Each recommendation comes with a confidence score, natural language reasoning, a cost delta breakdown showing the monthly spend impact of the drift, and a severity classification (low/medium/high/critical) based on security and cost implications. The system then automatically raises the appropriate pull request to the team's GitHub repo, closing the loop from detection to resolution.
The entire pipeline is instrumented with Datadog for observability — tracing the CloudFormation fetch, the diff computation, the Claude API call latency and token usage, and the PR creation. Drift detections and their severity scores are emitted as custom Datadog metrics, powering a dashboard that shows drift trends over time and a monitor that alerts when high-severity drift is detected in production stacks. The end result is that when an on-call engineer makes a 3 AM console change to fix a production incident, the system tells them the next morning whether that decision was right, partially right, or wrong — and generates the correct fix either way.

---

### Testing the Datadog Utilities

The `handler.py` file provides a CLI to validate the Datadog integration. It uses
the utility functions in `utils/datadog.py` to fetch logs, traces, metrics, and
events from the Datadog API.

#### Setup

```bash
pip install -r requirements.txt
```

Ensure your `.env` contains:

```
DD_API_KEY=<your-datadog-api-key>
DD_APP_KEY=<your-datadog-application-key>
```

#### Usage

```bash
# Fetch observability data across ALL services (last 12 hours)
python3 handler.py

# Fetch observability data for a specific service
python3 handler.py <service-name>
```

#### Example Output

```
==================================================
  Observability data for: prompt-analyzer
==================================================

--- Logs ---
  [2026-02-20T21:35:11.964Z] Sent message: {"message": "Hello, dsm sqs!"}
  [2026-02-20T21:35:10.266Z] Received message: {"message": "Hello, dsm sqs!"}

--- Traces ---
  sqs.getqueueattributes - 12345ns
  s3.listobjectsv2 - 67890ns
  consume_message - 11234ns

--- Metrics ---
  (none)

--- Events ---
  (none)
```

#### What It Tests

| Data Source | API Endpoint                      | Query Format                |
|-------------|-----------------------------------|-----------------------------|
| Logs        | `POST /v2/logs/events/search`     | `service:<name>` or `*`     |
| Traces      | `POST /v2/spans/events/search`    | `service:<name>` or `*`     |
| Metrics     | `GET /v1/query`                   | `avg:trace.http.request.duration{service:<name>}` |
| Events      | `GET /v1/events`                  | `service:<name>` or `*`     |
