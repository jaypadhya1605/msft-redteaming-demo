<#
.SYNOPSIS
    Runs a cloud red-team scan on one or more model deployments, the same request the portal wizard sends
    (Evaluations > Red team > Create, Model target). Keyless: uses your az login.

.DESCRIPTION
    Use it to accept or reject a candidate model in a separate evaluation Foundry project, from code, so the
    scan can be rerun on every model or guardrail change (or in CI).
    - One red team (an evaluation) with one run per deployment, so the portal shows them side by side.
    - Risk categories map to Microsoft's built-in safety evaluators. The service generates the attack
      objectives for each category, then applies each strategy plus a baseline (no strategy).
    - The deployment's guardrail stays in place, so the scan measures model + guardrail together.
    Results show in the portal under Evaluations > Red team. Export every scored attack for the acceptance
    report with ..\evidence\export-redteam-results.ps1.

.EXAMPLE
    pwsh -File .\run-model-scan.ps1 -Deployments gpt-5.4-mini-minimal -RiskCategories hate_unfairness,violence `
        -AttackStrategies Base64,Flip -ScanName rt-model-mini -Wait

.EXAMPLE
    # Guardrail comparison: the same scan on the three guardrail variants, side by side in the portal.
    pwsh -File .\run-model-scan.ps1 -Deployments gpt-5.4-mini-minimal,gpt-5.4-mini-default,gpt-5.4-mini-strict `
        -ScanName rt-guardrail-compare -Wait

.EXAMPLE
    pwsh -File .\run-model-scan.ps1 -SubscriptionId <sub-id> `
        -ProjectEndpoint https://<foundry-account>.services.ai.azure.com/api/projects/<project> `
        -Deployments <candidate-a>,<candidate-b> -ScanName <model-acceptance-scan>

.NOTES
    With pwsh -File, separate list values with commas and no spaces.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,
    [string]$ProjectEndpoint = $env:FOUNDRY_PROJECT_ENDPOINT,
    [string[]]$Deployments = @('gpt-5.4-mini-default'),
    # Any of: violence, hate_unfairness, sexual, self_harm, ungrounded_attributes, code_vulnerability.
    [string[]]$RiskCategories = @('violence', 'hate_unfairness', 'sexual', 'self_harm', 'ungrounded_attributes', 'code_vulnerability'),
    [string[]]$AttackStrategies = @('Base64', 'Flip', 'Morse', 'Tense', 'Jailbreak'),
    # The portal wizard sends 5.
    [ValidateRange(1, 10)]
    [int]$NumTurns = 5,
    [Parameter(Mandatory)]
    [string]$ScanName,
    # Waits for every run to finish and prints the result counts.
    [switch]$Wait
)

$ErrorActionPreference = 'Stop'
$api = 'api-version=2025-11-15-preview'
if (-not $SubscriptionId -or -not $ProjectEndpoint) {
    throw 'Set -SubscriptionId and -ProjectEndpoint, or the AZURE_SUBSCRIPTION_ID and FOUNDRY_PROJECT_ENDPOINT environment variables.'
}

# Evaluator versions the portal wizard used (Oct 2026).
$evaluators = @{
    violence              = @{ name = 'Violence'; evaluator = 'builtin.violence'; version = '5' }
    hate_unfairness       = @{ name = 'Hate and unfairness'; evaluator = 'builtin.hate_unfairness'; version = '5' }
    sexual                = @{ name = 'Sexual'; evaluator = 'builtin.sexual'; version = '5' }
    self_harm             = @{ name = 'Self-harm'; evaluator = 'builtin.self_harm'; version = '5' }
    ungrounded_attributes = @{ name = 'Ungrounded attributes'; evaluator = 'builtin.ungrounded_attributes'; version = '4' }
    code_vulnerability    = @{ name = 'Code vulnerability'; evaluator = 'builtin.code_vulnerability'; version = '4' }
}

# pwsh -File passes "a,b" as one string.
$Deployments = @($Deployments -split ',' | ForEach-Object Trim | Where-Object { $_ })
$RiskCategories = @($RiskCategories -split ',' | ForEach-Object Trim | Where-Object { $_ })
$AttackStrategies = @($AttackStrategies -split ',' | ForEach-Object Trim | Where-Object { $_ })
$unknown = @($RiskCategories | Where-Object { -not $evaluators.ContainsKey($_) })
if ($unknown.Count) { throw "Unknown risk category: $($unknown -join ', '). Use any of: $($evaluators.Keys -join ', ')." }

function Invoke-Foundry {
    param([string]$Method = 'Get', [string]$Path, $Body)
    $uri = "$ProjectEndpoint/$Path" + $(if ($Path.Contains('?')) { '&' } else { '?' }) + $api
    $params = @{ Method = $Method; Uri = $uri; Headers = $script:headers; TimeoutSec = 300 }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json; charset=utf-8'
        $params.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 20 -Compress))
    }
    try { Invoke-RestMethod @params }
    catch { throw "$Method $Path failed: $($_.Exception.Message) $($_.ErrorDetails.Message)" }
}

function Get-Token { az account get-access-token --resource https://ai.azure.com --subscription $SubscriptionId --query accessToken -o tsv }

$token = Get-Token
if (-not $token) { throw "Could not get a token for https://ai.azure.com. Run 'az login' first." }
$script:headers = @{ Authorization = 'Bearer ' + $token }
$token = $null

try {
    $redTeam = Invoke-Foundry -Method Post -Path 'openai/evals' -Body @{
        name               = $ScanName
        data_source_config = @{ type = 'azure_ai_source'; scenario = 'red_team' }
        testing_criteria   = @($RiskCategories | ForEach-Object {
                $e = $evaluators[$_]
                @{ type = 'azure_ai_evaluator'; name = $e.name; evaluator_name = $e.evaluator; evaluator_version = $e.version }
            })
    }

    $runs = foreach ($deployment in $Deployments) {
        Invoke-Foundry -Method Post -Path "openai/evals/$($redTeam.id)/runs" -Body @{
            name        = "$ScanName-$deployment"
            data_source = @{
                type                   = 'azure_ai_red_team'
                item_generation_params = @{ type = 'red_team'; attack_strategies = $AttackStrategies; num_turns = $NumTurns }
                target                 = @{ type = 'azure_ai_model'; model = $deployment }
            }
        }
    }
    Write-Host "Red team '$ScanName' ($($redTeam.id)): $(@($runs).Count) run(s). Categories: $($RiskCategories -join ', '). Strategies: baseline + $($AttackStrategies -join ', ')."
    $runs | ForEach-Object { Write-Host "  $($_.data_source.target.model): $($_.id) $($_.status)" }
    Write-Host 'Portal: Build > Evaluations > Red team.'

    if ($Wait) {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $tokenAge = [Diagnostics.Stopwatch]::StartNew()
        $runs = @($runs)
        while (@($runs | Where-Object status -notin 'completed', 'failed', 'canceled').Count) {
            Start-Sleep -Seconds 30
            if ($tokenAge.Elapsed.TotalMinutes -gt 40) {
                $script:headers.Authorization = 'Bearer ' + (Get-Token)
                $tokenAge.Restart()
            }
            $runs = @($runs | ForEach-Object { Invoke-Foundry -Path "openai/evals/$($redTeam.id)/runs/$($_.id)" })
            Write-Host ("{0:mm\:ss} {1}" -f $timer.Elapsed, (($runs | ForEach-Object { "$($_.data_source.target.model) $($_.status)" }) -join '; '))
        }
        foreach ($run in $runs) {
            $c = $run.result_counts
            Write-Host ("{0}: {1}, {2} attacks, {3} failed (reported), {4} errored. Duration {5}." -f $run.data_source.target.model, $run.status, $c.total, $c.failed, $c.errored, $run.duration)
            if ($run.error) { Write-Warning "Run error: $($run.error | ConvertTo-Json -Depth 5 -Compress)" }
        }
        Write-Host "Export for the acceptance report: ..\evidence\export-redteam-results.ps1 -RedTeamId $($redTeam.id) -Name $ScanName"
        Write-Host 'Reported failures include guardrail blocks and echoes; review them before quoting an attack success rate.'
    }
}
finally {
    $script:headers = $null
}
