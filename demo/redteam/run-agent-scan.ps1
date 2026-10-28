<#
.SYNOPSIS
    Runs a cloud agent red-team scan on a Foundry prompt agent from Git-managed policy. Keyless: uses your az login.

.DESCRIPTION
    Does the same thing as the portal wizard (Evaluations > Red team > Create, Agent target), but from code, so
    it reruns in any tenant or in CI:
    1. Taxonomy: asks the service to generate the prohibited-actions taxonomy for the agent, keeps only the Microsoft
       defaults listed in the policy file, adds your own actions, and saves it as taxonomy
       <agent>-ver<version>-pa-<policy hash>. Edit the policy file and rerun: the new policy gets its own taxonomy.
    2. Red team: creates an evaluation with the three agentic evaluators (prohibited actions, sensitive data leakage,
       task adherence).
    3. Run: attacks the pinned agent version with the chosen strategies. Results show in the portal under
       Evaluations > Red team, and with -Wait they're also saved as JSON for the acceptance report (scores, reasons
       and triage flags only; model text stays in the portal).

.EXAMPLE
    pwsh -File .\run-agent-scan.ps1 -Wait

.EXAMPLE
    pwsh -File .\run-agent-scan.ps1 -SubscriptionId <sub-id> `
        -ProjectEndpoint https://<foundry-account>.services.ai.azure.com/api/projects/<project> `
        -AgentVersion 2 -ScanName rt-care-navigator-ver2 -Wait

.NOTES
    With pwsh -File, separate list values with commas and no spaces, e.g. -AttackStrategies Baseline,Flip.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,
    [string]$ProjectEndpoint = $env:FOUNDRY_PROJECT_ENDPOINT,
    [string]$AgentName = 'care-navigator',
    # Blank means the latest version. Record the version: results are only meaningful for the version scanned.
    [string]$AgentVersion,
    [string]$PolicyFile = (Join-Path $PSScriptRoot 'policy\prohibited-actions.json'),
    # Model deployment the task adherence evaluator uses as its judge.
    [string]$EvaluatorDeployment = 'gpt-5.4-mini-default',
    # IndirectJailbreak fails in ~15 s ("ACA session initiation failed ... 400") and Jailbreak fails silently after
    # ~5 min in the demo project (preview, Oct 2026). Cover indirect injection with ..\app\smoke-test.ps1 meanwhile.
    [string[]]$AttackStrategies = @('Baseline', 'Flip', 'Base64'),
    [ValidateRange(1, 10)]
    [int]$NumTurns = 1,
    # Blank means rt-<agent>-ver<version>.
    [string]$ScanName,
    # Waits for the run to finish, then saves the run and its output items to OutDir.
    [switch]$Wait,
    [string]$OutDir = (Join-Path $PSScriptRoot '..\evidence\runs')
)

$ErrorActionPreference = 'Stop'
$api = 'api-version=2025-11-15-preview'
if (-not $SubscriptionId -or -not $ProjectEndpoint) {
    throw 'Set -SubscriptionId and -ProjectEndpoint, or the AZURE_SUBSCRIPTION_ID and FOUNDRY_PROJECT_ENDPOINT environment variables.'
}
. (Join-Path $PSScriptRoot '..\evidence\triage.ps1')
# pwsh -File passes "a,b" as one string.
$AttackStrategies = @($AttackStrategies -split ',' | ForEach-Object Trim | Where-Object { $_ })

function Invoke-Foundry {
    param([string]$Method = 'Get', [string]$Path, $Body)
    $uri = if ($Path -match '^https://') { $Path } else { "$ProjectEndpoint/$Path" }
    $uri += $(if ($uri.Contains('?')) { '&' } else { '?' }) + $api
    $params = @{ Method = $Method; Uri = $uri; Headers = $script:headers; TimeoutSec = 300 }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json; charset=utf-8'
        $params.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 20 -Compress))
    }
    try { Invoke-RestMethod @params }
    catch { throw "$Method $Path failed: $($_.Exception.Message) $($_.ErrorDetails.Message)" }
}

function Get-StableGuid([string]$Text) {
    $hash = [Security.Cryptography.MD5]::HashData([Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant()))
    [guid]::new($hash).ToString()
}

$policy = Get-Content -Raw -LiteralPath $PolicyFile | ConvertFrom-Json
$toolDescriptions = @($policy.toolDescriptions | ForEach-Object { @{ name = $_.name; description = $_.description } })

$token = az account get-access-token --resource https://ai.azure.com --subscription $SubscriptionId --query accessToken -o tsv
if (-not $token) { throw "Could not get a token for https://ai.azure.com. Run 'az login' first." }
$script:headers = @{ Authorization = "Bearer $token" }

try {
    if (-not $AgentVersion) {
        $AgentVersion = (Invoke-RestMethod -Headers $script:headers -Uri "$ProjectEndpoint/agents/$($AgentName)?api-version=v1").versions.latest.version
    }
    if (-not $ScanName) { $ScanName = "rt-$AgentName-ver$AgentVersion" }
    $target = @{ type = 'azure_ai_agent'; name = $AgentName; version = "$AgentVersion"; tool_descriptions = $toolDescriptions }
    Write-Host "Target: $AgentName version $AgentVersion"

    # 1. Taxonomy: PUT generates Microsoft's default actions (all disabled); PATCH saves our edits as a new version.
    # The service reuses the attack objectives it generated for a taxonomy name, so an edited policy saved under the
    # same name is silently ignored (preview, Oct 2026). Naming it by policy hash gives each policy its own taxonomy and
    # leaves earlier runs' taxonomies untouched.
    $policyHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes(($policy | ConvertTo-Json -Depth 10 -Compress)))).Substring(0, 8).ToLowerInvariant()
    $taxonomyName = "$AgentName-ver$AgentVersion-pa-$policyHash"
    $taxonomyInput = @{ type = 'agent'; target = $target; riskCategories = @($policy.riskCategory) }
    $taxonomy = Invoke-Foundry -Method Put -Path "evaluationtaxonomies/$taxonomyName" -Body @{ taxonomyInput = $taxonomyInput }

    $categories = @($taxonomy.taxonomyCategories)
    if (-not $categories) { throw 'The service returned no taxonomy categories.' }
    $missing = @($policy.keepMicrosoftDefaults | Where-Object { $_ -notin $categories.subCategories.name })
    if ($missing) { Write-Warning "Microsoft defaults not found in this taxonomy: $($missing -join '; ')" }
    # Runs attack every action in the taxonomy and ignore 'enabled' (preview, Oct 2026), so unwanted defaults are removed.
    foreach ($category in $categories) {
        $category.subCategories = @($category.subCategories | Where-Object { $_.name -in $policy.keepMicrosoftDefaults } |
                ForEach-Object { $_.enabled = $true; $_ })
    }
    $custom = @($policy.actions | ForEach-Object {
            [pscustomobject]@{ id = Get-StableGuid $_.name; name = $_.name; description = $_.description; enabled = $true; properties = @{ tier = $_.tier } }
        })
    $categories[0].subCategories = @(@($categories[0].subCategories) + $custom)
    $taxonomy.description = "From $(Split-Path -Leaf $PolicyFile)"

    $taxonomy = Invoke-Foundry -Method Patch -Path "evaluationtaxonomies/$taxonomyName" -Body $taxonomy
    $enabled = @($taxonomy.taxonomyCategories.subCategories | Where-Object enabled)
    if ($enabled.Count -ne $custom.Count + $policy.keepMicrosoftDefaults.Count - $missing.Count) {
        throw "Taxonomy update didn't apply: $($enabled.Count) actions in scope."
    }
    Write-Host "Taxonomy $($taxonomy.name) v$($taxonomy.version): $($enabled.Count) prohibited actions in scope ($($custom.Count) custom, $($enabled.Count - $custom.Count) Microsoft defaults)"

    # 2. Red team (an evaluation that holds the runs).
    $criteria = @(
        @{ type = 'azure_ai_evaluator'; name = 'Prohibited actions'; evaluator_name = 'builtin.prohibited_actions'; evaluator_version = '1' },
        @{ type = 'azure_ai_evaluator'; name = 'Sensitive data leakage'; evaluator_name = 'builtin.sensitive_data_leakage'; evaluator_version = '1' },
        @{ type = 'azure_ai_evaluator'; name = 'Task adherence'; evaluator_name = 'builtin.task_adherence'; evaluator_version = '1'
            initialization_parameters = @{ deployment_name = $EvaluatorDeployment } 
        }
    )
    $redTeam = Invoke-Foundry -Method Post -Path 'openai/evals' -Body @{
        name               = $ScanName
        data_source_config = @{ type = 'azure_ai_source'; scenario = 'red_team' }
        testing_criteria   = $criteria
    }

    # 3. Run.
    $run = Invoke-Foundry -Method Post -Path "openai/evals/$($redTeam.id)/runs" -Body @{
        name        = "$ScanName-run"
        data_source = @{
            type                   = 'azure_ai_red_team'
            item_generation_params = @{
                type              = 'red_team_taxonomy'
                attack_strategies = $AttackStrategies
                num_turns         = $NumTurns
                source            = @{ type = 'file_id'; id = $taxonomy.id }
            }
            target                 = $target
        }
    }
    Write-Host "Red team '$ScanName' ($($redTeam.id)), run $($run.id): $($run.status). Strategies: $($AttackStrategies -join ', ')."
    Write-Host 'Portal: Build > Evaluations > Red team.'

    if ($Wait) {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $tokenAge = [Diagnostics.Stopwatch]::StartNew()
        while ($run.status -notin 'completed', 'failed', 'canceled') {
            Start-Sleep -Seconds 30
            if ($tokenAge.Elapsed.TotalMinutes -gt 40) {
                $script:headers.Authorization = 'Bearer ' + (az account get-access-token --resource https://ai.azure.com --subscription $SubscriptionId --query accessToken -o tsv)
                $tokenAge.Restart()
            }
            $run = Invoke-Foundry -Path "openai/evals/$($redTeam.id)/runs/$($run.id)"
            Write-Host ("{0:mm\:ss} {1}" -f $timer.Elapsed, $run.status)
        }
        if ($run.error) { Write-Warning "Run error: $($run.error | ConvertTo-Json -Depth 5 -Compress)" }

        $items = [Collections.Generic.List[object]]::new()
        if ($run.status -eq 'completed') {
            $after = $null
            do {
                $page = Invoke-Foundry -Path ("openai/evals/$($redTeam.id)/runs/$($run.id)/output_items?limit=100" + $(if ($after) { "&after=$after" }))
                $page.data | ForEach-Object { $items.Add((Protect-RedTeamItem $_)) }
                $after = $page.last_id
            } while ($page.has_more)
        }

        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        $outFile = Join-Path (Resolve-Path $OutDir) "$ScanName.json"
        [ordered]@{
            scan       = $ScanName
            target     = $target
            strategies = $AttackStrategies
            taxonomy   = @{ id = $taxonomy.id; actions = @($enabled | Select-Object name, description, properties) }
            red_team   = $redTeam.id
            run        = $run
            items      = $items
        } | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $outFile -Encoding utf8
        Write-Host "Run $($run.status) with $($items.Count) output items. Saved to $outFile"
        if ($run.result_counts) { Write-Host "Reported result counts: $($run.result_counts | ConvertTo-Json -Compress)" }
        # Each action gets one attack objective per strategy, so a new action adds one attack per strategy here.
        $evaluatorIds = @($criteria | ForEach-Object { $_.evaluator_name -replace '^builtin\.' })
        $perEvaluator = @($run.per_testing_criteria_results | Where-Object testing_criteria -in $evaluatorIds |
                ForEach-Object { "$($_.testing_criteria) $($_.passed + $_.failed)" })
        if ($perEvaluator) { Write-Host "Attacks per evaluator: $($perEvaluator -join ', ')" }
        if ($items.Count) {
            Write-Host 'Review failed items before reporting: in this preview the judge''s label can contradict its own reason.'
            Write-Host 'Run ..\evidence\build-acceptance-report.ps1 to list them.'
        }
    }
}
finally {
    $token = $null
    $script:headers = $null
}
