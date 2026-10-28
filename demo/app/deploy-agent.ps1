<#
.SYNOPSIS
    Creates the Care Navigator prompt agent in a Foundry project, adding a new version on every run. Keyless: uses your az login.

.DESCRIPTION
    Agents aren't Azure Resource Manager resources, so Bicep and Terraform can't create them. Run this after
    main.bicep (Foundry project, model deployments, AI Search connection) and load-kb.ps1 (the index).
    - Reads the instructions from a text file, so the weak (v1) and hardened (v2) drafts are versioned in Git.
    - Attaches the Azure AI Search tool directly on the agent (not through a toolbox), which agent red teaming supports.
    - Prints the new version number. Red-team scans target a specific version, so record it.

.EXAMPLE
    pwsh -File .\deploy-agent.ps1

.EXAMPLE
    pwsh -File .\deploy-agent.ps1 -SubscriptionId <sub-id> `
        -ProjectEndpoint https://<foundry-account>.services.ai.azure.com/api/projects/<project> `
        -SearchConnectionName <search-connection> -InstructionsFile .\care-navigator-v2.txt
#>
[CmdletBinding()]
param(
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,
    [string]$ProjectEndpoint = $env:FOUNDRY_PROJECT_ENDPOINT,
    [string]$AgentName = 'care-navigator',
    [string]$ModelDeployment = 'gpt-5.4-mini-default',
    # Name of the project's AI Search connection (main.bicep names it srch-<baseName>-<nameSuffix>).
    [string]$SearchConnectionName = $env:SEARCH_CONNECTION_NAME,
    [string]$IndexName = 'care-navigator-kb',
    [string]$InstructionsFile = (Join-Path $PSScriptRoot 'care-navigator-v1.txt'),
    [ValidateSet('simple', 'semantic', 'vector', 'vector_simple_hybrid', 'vector_semantic_hybrid')]
    [string]$QueryType = 'vector_semantic_hybrid',
    [ValidateRange(1, 50)]
    [int]$TopK = 5,
    # Optional OData filter applied to every search the agent makes, for example to keep other patients' records
    # out of reach: "category ne 'patient-record' or id eq 'pat-TEST-100201'". In production the app sets it per user.
    [string]$Filter,
    # Matches the portal default for reasoning models. Pass '' for a model without reasoning support.
    [ValidateSet('', 'minimal', 'low', 'medium', 'high')]
    [string]$ReasoningEffort = 'low'
)

$ErrorActionPreference = 'Stop'
$api = 'api-version=v1'
if (-not $SubscriptionId -or -not $ProjectEndpoint -or -not $SearchConnectionName) {
    throw 'Set -SubscriptionId, -ProjectEndpoint and -SearchConnectionName, or the AZURE_SUBSCRIPTION_ID, FOUNDRY_PROJECT_ENDPOINT and SEARCH_CONNECTION_NAME environment variables.'
}

$instructions = (Get-Content -Raw -LiteralPath $InstructionsFile).Trim()
if (-not $instructions) { throw "Instructions file is empty: $InstructionsFile" }

$token = az account get-access-token --resource https://ai.azure.com --subscription $SubscriptionId --query accessToken -o tsv
if (-not $token) { throw "Could not get a token for https://ai.azure.com. Run 'az login' first." }
$headers = @{ Authorization = "Bearer $token" }

try {
    # The tool needs the connection's full resource ID; looking it up keeps the script tenant-neutral.
    $connection = Invoke-RestMethod -Headers $headers -Uri "$ProjectEndpoint/connections/$($SearchConnectionName)?$api"

    $definition = @{
        kind         = 'prompt'
        model        = $ModelDeployment
        instructions = $instructions
        tools        = @(
            @{
                type            = 'azure_ai_search'
                azure_ai_search = @{
                    indexes = @(
                        @{
                            project_connection_id = $connection.id
                            index_name            = $IndexName
                            query_type            = $QueryType
                            top_k                 = $TopK
                        }
                    )
                }
            }
        )
    }
    if ($ReasoningEffort) { $definition.reasoning = @{ effort = $ReasoningEffort } }
    if ($Filter) { $definition.tools[0].azure_ai_search.indexes[0].filter = $Filter }

    $json = @{ definition = $definition } | ConvertTo-Json -Depth 10 -Compress
    $created = Invoke-RestMethod -Method Post -Headers $headers -Uri "$ProjectEndpoint/agents/$AgentName/versions?$api" `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))

    Write-Host "Created $AgentName version $($created.version): $ModelDeployment + $IndexName ($QueryType, top $TopK$(if ($Filter) { ", filter: $Filter" })), instructions from $(Split-Path -Leaf $InstructionsFile)."
}
finally {
    $token = $null
    $headers = $null
}
