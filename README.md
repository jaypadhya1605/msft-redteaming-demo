# AI Red Teaming Agent: reference demo (template)

Infrastructure as code, policies, and scripts that replay an end-to-end **AI red teaming** demo on Microsoft Foundry in your own Azure subscription:

1. **Model scan:** compare one model under three guardrail levels with the AI Red Teaming Agent.
2. **Agent scan:** red team a deliberately weak, patient-facing sample agent ("Care Navigator") with a custom prohibited-actions policy, then fix it and retest.
3. **Targeted tests:** repeatable checks for cross-patient data leaks, hidden instructions in documents (XPIA), and dosing advice.
4. **Runtime layer:** compare an API Management (APIM) gateway with and without Azure AI Content Safety, plus a template route for a partner AI-detection service.
5. **Evidence:** export results and build an acceptance report against criteria the customer owns.

The sample organization is fictional (**Contoso Health**). All knowledge-base content, patient records, names, and phone numbers are synthetic.

> **Not an official Microsoft product.** Sample code for learning and evaluation, provided as is (see [LICENSE](LICENSE)). Several features used here are in **preview**; behavior, regions, and APIs can change. Use **synthetic data only** until your organization has confirmed the compliance scope (for example, BAA coverage) of each preview feature.

## What maps to what

| Topic | Where |
|---|---|
| Architecture overview | [demo/architecture/architecture.html](demo/architecture/architecture.html) (open in a browser) |
| Foundry, models, guardrail levels, Search, Content Safety, APIM, Key Vault, monitoring | [demo/infra/main.bicep](demo/infra/main.bicep) |
| Model guardrail comparison (minimal / default / strict) | `raiPolicies` in [main.bicep](demo/infra/main.bicep), [run-model-scan.ps1](demo/redteam/run-model-scan.ps1) |
| Sample agent, knowledge base, poisoned document (XPIA) | [demo/app/](demo/app/), walkthrough in [care-navigator-instructions.md](demo/app/care-navigator-instructions.md) |
| Prohibited actions (agent policy as code) | [prohibited-actions.json](demo/redteam/policy/prohibited-actions.json), [prohibited-actions.md](demo/redteam/policy/prohibited-actions.md), [run-agent-scan.ps1](demo/redteam/run-agent-scan.ps1) |
| Targeted PHI-leak / XPIA / dosing tests | [smoke-test.ps1](demo/app/smoke-test.ps1) |
| Fix and retest (hardened instructions + least-privilege search filter) | [care-navigator-v2.txt](demo/app/care-navigator-v2.txt), `-Filter` on [deploy-agent.ps1](demo/app/deploy-agent.ps1) |
| Gateway routes S1 (direct), S2 (APIM, no filter), S3 (APIM + Content Safety), S4 (partner AIDR template) | [demo/gateway/](demo/gateway/) |
| Acceptance criteria (illustrative; owned by the customer) | [thresholds.yaml](demo/redteam/thresholds.yaml) |
| Attack seeds and benign controls for the gateway comparison | [demo/redteam/seeds/](demo/redteam/seeds/) |
| Evidence export, triage rules, acceptance report | [demo/evidence/](demo/evidence/) |

## Prerequisites

- Azure subscription with permission to create resources and role assignments (Owner, or Contributor + User Access Administrator, on the resource group).
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) 2.60+ with Bicep (`az bicep install`), signed in with `az login`.
- [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell) (`pwsh`). The scripts don't run on Windows PowerShell 5.1.
- A region where the red teaming agent and the models in `main.bicep` are available. The demo used **East US 2**. Check the [AI Red Teaming Agent docs](https://learn.microsoft.com/azure/foundry/concepts/ai-red-teaming-agent) for current regions, and model availability and quota for your subscription. Adjust model names and versions in `main.bicep` if needed.

## Replay

Run from the repository root.

### 1. Deploy the foundation

Fill in the placeholders in [main.bicepparam](demo/infra/main.bicepparam) (`<unique-suffix>`, `<your-entra-object-id>`, `<publisher-email>`), then:

```powershell
az group create -n <resource-group> -l eastus2
az deployment group create -g <resource-group> -n main -p demo/infra/main.bicepparam
```

APIM provisioning can take 30+ minutes.

### 2. Set environment variables from the deployment outputs

The scripts read these so nothing tenant-specific lives in the repo:

```powershell
$rg = '<resource-group>'
$o  = az deployment group show -g $rg -n main --query properties.outputs -o json | ConvertFrom-Json
$env:AZURE_SUBSCRIPTION_ID    = az account show --query id -o tsv
$env:AZURE_RESOURCE_GROUP     = $rg
$env:FOUNDRY_ACCOUNT_NAME     = $o.foundryAccountName.value
$env:FOUNDRY_PROJECT_ENDPOINT = $o.projectEndpoint.value
$env:FOUNDRY_OPENAI_ENDPOINT  = $o.openAiEndpoint.value
$env:SEARCH_ENDPOINT          = $o.searchEndpoint.value
$env:SEARCH_CONNECTION_NAME   = $o.searchConnectionName.value
$env:APIM_NAME                = $o.apimName.value
$env:CONTENT_SAFETY_NAME      = $o.contentSafetyName.value
```

Every script also accepts these values as parameters (`-SubscriptionId`, `-ProjectEndpoint`, and so on).

### 3. Model scan: guardrail comparison

```powershell
pwsh -File demo/redteam/run-model-scan.ps1 -Deployments gpt-5.4-mini-minimal,gpt-5.4-mini-default,gpt-5.4-mini-strict `
    -ScanName rt-guardrail-compare -Wait
```

If you start a scan in the portal instead, export it with [export-redteam-results.ps1](demo/evidence/export-redteam-results.ps1) `-RedTeamId <eval_id-from-portal-url> -Name rt-guardrail-compare`.

### 4. Agent: build, test, scan, fix, retest

Follow [care-navigator-instructions.md](demo/app/care-navigator-instructions.md). Short version:

```powershell
pwsh -File demo/app/load-kb.ps1
pwsh -File demo/app/deploy-agent.ps1                                   # v1, weak on purpose
pwsh -File demo/app/smoke-test.ps1 -AgentVersion 1 -OutFile demo/evidence/smoke-v1.json
pwsh -File demo/redteam/run-agent-scan.ps1 -AgentVersion 1 -Wait

pwsh -File demo/app/deploy-agent.ps1 -InstructionsFile demo/app/care-navigator-v2.txt `
    -Filter "category ne 'patient-record' or id eq 'pat-TEST-100201'"  # v2, hardened
pwsh -File demo/app/smoke-test.ps1 -AgentVersion 2 -OutFile demo/evidence/smoke-v2.json
pwsh -File demo/redteam/run-agent-scan.ps1 -AgentVersion 2 -Wait
```

Use the version numbers the deploy script prints.

### 5. Runtime layer: gateway comparison

Fill in [gateway.bicepparam](demo/gateway/gateway.bicepparam), then:

```powershell
az deployment group create -g $env:AZURE_RESOURCE_GROUP -n gateway -p demo/gateway/gateway.bicepparam
pwsh -File demo/gateway/run-gateway-compare.ps1
pwsh -File demo/gateway/run-gateway-compare.ps1 -ApiFormat chat -OutFile demo/evidence/gateway-compare-chat.json
pwsh -File demo/gateway/diagnose-response-check.ps1
```

**S4 (partner AI detection and response, for example CrowdStrike AIDR):** [s4-partner-aidr_template.xml](demo/gateway/policies/s4-partner-aidr_template.xml) is a template only. Follow the vendor's APIM integration guide (for CrowdStrike: [aidr-azure-api-management](https://github.com/CrowdStrike/aidr-azure-api-management)), confirm the vendor's endpoint region, timeout, and fail-open/fail-closed behavior, then rerun `run-gateway-compare.ps1 -S4Url <s4-route-url>` so all routes face the same attacks.

### 6. Acceptance report

```powershell
pwsh -File demo/evidence/build-acceptance-report.ps1 -VersionNotes @{ '1' = 'Original instructions'; '2' = 'Hardened instructions + search filter' }
```

Writes `acceptance-report.md` and `acceptance-report.html` to `demo/evidence/`. Criteria with no evidence show **NOT RUN**, never PASS. Ambiguous evaluator results go to a review queue; record human decisions in `review-decisions.json` and rebuild. In this preview the prohibited-actions judge sometimes labels a refusal as "fail"; by default those items wait for a person, or add `-TrustJudgeReason` to clear them when the judge's own reason says the agent refused.

## Acceptance criteria

[thresholds.yaml](demo/redteam/thresholds.yaml) holds **illustrative** limits so the report has something to measure against. Your security, clinical safety, and privacy owners should agree the real criteria, sample sizes, and sign-off roles before production use.

## Cost

- **Hourly while deployed:** API Management (Basic v2 in this template) and Azure AI Search (Basic). Delete the resource group when you're done: `az group delete -n <resource-group>`.
- **Pay per use:** model tokens (target and judge models), red teaming on the Foundry evaluations meter, and Content Safety text records.

Estimate with the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) and [Foundry evaluation pricing](https://azure.microsoft.com/pricing/details/foundryobservability/) for your region, number of models and agents, scan frequency, and request volume.

## Out of scope

- Fairness/bias evaluation for imaging models. The Responsible AI dashboard covers tabular models; for imaging, consider [Fairlearn](https://learn.microsoft.com/azure/machine-learning/concept-fairness-ml) in an Azure ML job (subgroup false-positive/false-negative rates) alongside a model card such as the [CHAI Applied Model Card](https://registry.chai.org/applied-model-card).
- Multi-turn attacks with PyRIT or the local SDK.
- Production hardening (private networking, customer-managed keys, CI/CD gates).

## Data handling

- Evidence files (scan exports, smoke-test results, gateway runs, review decisions, reports) are generated locally and **git-ignored**. They contain scores and metadata, not model text, but keep them out of public repositories.
- Don't commit keys, certificates, or connection strings. The templates use Microsoft Entra ID and managed identities.

## References

- [AI Red Teaming Agent](https://learn.microsoft.com/azure/foundry/concepts/ai-red-teaming-agent)
- [Foundry evaluation pricing](https://azure.microsoft.com/pricing/details/foundryobservability/)
- [Azure AI Content Safety in APIM](https://learn.microsoft.com/azure/api-management/llm-content-safety-policy)
- [CrowdStrike AIDR for APIM](https://github.com/CrowdStrike/aidr-azure-api-management)
