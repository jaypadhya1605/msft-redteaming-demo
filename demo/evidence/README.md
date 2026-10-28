# Evidence

Scripts only. Everything they produce is written here locally and git-ignored:

| File | Produced by |
|---|---|
| `runs/<scan>.json` | [run-model-scan.ps1](../redteam/run-model-scan.ps1), [run-agent-scan.ps1](../redteam/run-agent-scan.ps1) (`-Wait`), or [export-redteam-results.ps1](export-redteam-results.ps1) |
| `smoke-v<N>.json` | [smoke-test.ps1](../app/smoke-test.ps1) `-AgentVersion <N> -OutFile` |
| `gateway-compare.json`, `gateway-compare-chat.json` | [run-gateway-compare.ps1](../gateway/run-gateway-compare.ps1) |
| `gateway-diagnostics.json` | [diagnose-response-check.ps1](../gateway/diagnose-response-check.ps1) |
| `review-decisions.json` | You: human decisions on review-queue items |
| `acceptance-report.md`, `acceptance-report.html` | [build-acceptance-report.ps1](build-acceptance-report.ps1) |

[triage.ps1](triage.ps1) holds the shared triage rules (dot-sourced by the report, agent-scan, and export scripts).

Exports keep scores, evaluator reasons, and metadata, not model answers. Review them before sharing outside your organization.
