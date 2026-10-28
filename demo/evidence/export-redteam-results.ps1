<#
.SYNOPSIS
    Saves a red team's runs and every scored attack to JSON for the evidence pack. Keyless: uses your az login.

.DESCRIPTION
    Use it for red teams started in the portal (for example the model scan) or with ..\redteam\run-model-scan.ps1.
    run-agent-scan.ps1 -Wait already saves its own results. build-acceptance-report.ps1 reads the files named in its
    -ModelScanFile and -AgentScanFiles parameters.
    Model text is not saved: each item keeps its scores, the evaluator's reason, and triage flags (triage.ps1).
    Find the red team ID in the portal URL: .../build/evaluations/<eval_...>/run/<evalrun_...>

.EXAMPLE
    pwsh -File .\export-redteam-results.ps1 -RedTeamId <eval_id-from-portal-url> -Name rt-guardrail-compare
#>
[CmdletBinding()]
param(
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,
    [string]$ProjectEndpoint = $env:FOUNDRY_PROJECT_ENDPOINT,
    [Parameter(Mandatory)]
    [string]$RedTeamId,
    # File name for the export. Blank means the red team ID.
    [string]$Name,
    [string]$OutDir = (Join-Path $PSScriptRoot 'runs')
)

$ErrorActionPreference = 'Stop'
$api = 'api-version=2025-11-15-preview'
if (-not $SubscriptionId -or -not $ProjectEndpoint) {
    throw 'Set -SubscriptionId and -ProjectEndpoint, or the AZURE_SUBSCRIPTION_ID and FOUNDRY_PROJECT_ENDPOINT environment variables.'
}
. (Join-Path $PSScriptRoot 'triage.ps1')

$token = az account get-access-token --resource https://ai.azure.com --subscription $SubscriptionId --query accessToken -o tsv
if (-not $token) { throw "Could not get a token for https://ai.azure.com. Run 'az login' first." }
$headers = @{ Authorization = "Bearer $token" }

function Get-Foundry([string]$Path) {
    Invoke-RestMethod -Headers $headers -TimeoutSec 300 -Uri ("$ProjectEndpoint/$Path" + $(if ($Path.Contains('?')) { '&' } else { '?' }) + $api)
}

try {
    $redTeam = Get-Foundry "openai/evals/$RedTeamId"
    $runs = @((Get-Foundry "openai/evals/$RedTeamId/runs?limit=100").data)
    $export = foreach ($run in $runs) {
        $items = [Collections.Generic.List[object]]::new()
        if ($run.status -eq 'completed') {
            $after = $null
            do {
                $page = Get-Foundry ("openai/evals/$RedTeamId/runs/$($run.id)/output_items?limit=100" + $(if ($after) { "&after=$after" }))
                $page.data | ForEach-Object { $items.Add((Protect-RedTeamItem $_)) }
                $after = $page.last_id
            } while ($page.has_more)
        }
        Write-Host ("{0} ({1}): {2}, {3} scored attacks" -f $run.name, $run.id, $run.status, $items.Count)
        [ordered]@{ run = $run; items = $items }
    }
}
finally {
    $token = $null
    $headers = $null
}

if (-not $Name) { $Name = $RedTeamId }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path (Resolve-Path $OutDir) "$Name.json"
[ordered]@{ scan = $Name; red_team = $RedTeamId; testing_criteria = $redTeam.testing_criteria; runs = @($export) } |
    ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $outFile -Encoding utf8
Write-Host "Saved to $outFile"
