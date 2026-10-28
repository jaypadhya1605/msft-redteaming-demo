// AI Red Teaming demo template - core infrastructure (keyless, Entra ID only). Synthetic data only.
// Deploy: az deployment group create -g <resource-group> --subscription <sub-id> -f main.bicep -p main.bicepparam
// Note: raiPolicies uses API 2026-03-01 and the model versions below were current in Oct 2026. Check region and model
// availability before deploying, and adjust versions or capacities to what your subscription offers.

targetScope = 'resourceGroup'

@description('Azure region for all resources. Red Teaming Agent cloud runs are supported in East US 2.')
param location string = resourceGroup().location

@description('Region for AI Search. Separate because Search capacity varies by region; the agent tool works cross-region.')
param searchLocation string = location

@description('Workload token used in resource names.')
param baseName string = 'redteam'

@description('Suffix used in globally unique resource names.')
param nameSuffix string

@description('Foundry project name.')
param projectName string = 'redteam-demo'

@description('Entra object ID of the presenter; receives data-plane roles for keyless access.')
param presenterObjectId string

@description('API Management publisher email.')
param publisherEmail string

@description('DataZoneStandard capacity (K TPM) for each gpt-5.4-mini deployment.')
param chatCapacity int = 100

@description('DataZoneStandard capacity (K TPM) for gpt-oss-120b.')
param ossCapacity int = 100

@description('DataZoneStandard capacity (K TPM) for text-embedding-3-small.')
param embeddingCapacity int = 50

param tags object = {
  project: 'ai-redteaming-demo'
  dataClassification: 'synthetic'
}

var foundryName = 'fndry-${baseName}-${nameSuffix}'
var searchName = 'srch-${baseName}-${nameSuffix}'
var contentSafetyName = 'cs-${baseName}-${nameSuffix}'
var keyVaultName = 'kv-${baseName}-${nameSuffix}'
var apimName = 'apim-${baseName}-${nameSuffix}'
var logName = 'log-${baseName}-${nameSuffix}'
var appInsightsName = 'appi-${baseName}-${nameSuffix}'

var roleIds = {
  foundryUser: '53ca6127-db72-4b80-b1b0-d745d6d5456d'
  cognitiveServicesUser: 'a97b65f3-24c7-4388-baec-2e87135dc908'
  cognitiveServicesOpenAIUser: '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'
  searchIndexDataContributor: '8ebe5a00-799e-43f5-93ac-243d3dce84a7'
  searchServiceContributor: '7ca78c08-252a-4471-8644-bb5ff32d4ba0'
  keyVaultSecretsOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
  keyVaultSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
}

// ---------- Observability ----------

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: law.id
  }
}

// ---------- Foundry resource + project ----------

resource foundry 'Microsoft.CognitiveServices/accounts@2025-09-01' = {
  name: foundryName
  location: location
  tags: tags
  kind: 'AIServices'
  sku: { name: 'S0' }
  identity: { type: 'SystemAssigned' }
  properties: {
    allowProjectManagement: true
    customSubDomainName: foundryName
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
    networkAcls: { defaultAction: 'Allow' }
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-09-01' = {
  parent: foundry
  name: projectName
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'AI Red Teaming Demo'
    description: 'AI Red Teaming Agent demo: model scan, agent scan, gateway comparison (synthetic data).'
  }
}

resource appInsightsConnection 'Microsoft.CognitiveServices/accounts/projects/connections@2025-09-01' = {
  parent: project
  name: appInsightsName
  properties: {
    category: 'AppInsights'
    target: appInsights.id
    authType: 'ApiKey'
    credentials: { key: appInsights.properties.ConnectionString }
    metadata: {
      ApiType: 'Azure'
      ResourceId: appInsights.id
    }
  }
}

// Created last in the account's write chain so a Search capacity issue can't block guardrails or models.
resource searchConnection 'Microsoft.CognitiveServices/accounts/projects/connections@2025-09-01' = {
  parent: project
  name: searchName
  dependsOn: [deployments]
  properties: {
    category: 'CognitiveSearch'
    target: 'https://${search.name}.search.windows.net'
    authType: 'AAD'
    metadata: {
      ApiType: 'Azure'
      ResourceId: search.id
      location: search.location
    }
  }
}

// ---------- Guardrails (RAI policies) ----------
// API severityThreshold = lowest severity that gets blocked: 'Low' = most restrictive, 'High' = least.

var harmCategories = ['Hate', 'Sexual', 'Violence', 'Selfharm']

var strictFilters = concat(
  map(harmCategories, c => { name: c, source: 'Prompt', enabled: true, blocking: true, severityThreshold: 'Low' }),
  map(harmCategories, c => { name: c, source: 'Completion', enabled: true, blocking: true, severityThreshold: 'Low' }),
  [
    { name: 'Jailbreak', source: 'Prompt', enabled: true, blocking: true }
    { name: 'Indirect Attack', source: 'Prompt', enabled: true, blocking: true }
    { name: 'Indirect Attack', source: 'PostToolCall', enabled: true, blocking: true }
    { name: 'Protected Material Text', source: 'Completion', enabled: true, blocking: true }
    { name: 'Protected Material Code', source: 'Completion', enabled: true, blocking: true }
  ]
)

// Weakest configuration available without Limited Access approval:
// input harm filters off, output harm filters block High only, jailbreak shield off.
// The service won't disable Indirect Attack; it coerces it to annotate-only, so it's declared that way.
var minimalFilters = concat(
  map(harmCategories, c => { name: c, source: 'Prompt', enabled: false, blocking: false, severityThreshold: 'High' }),
  map(harmCategories, c => { name: c, source: 'Completion', enabled: true, blocking: true, severityThreshold: 'High' }),
  [
    { name: 'Jailbreak', source: 'Prompt', enabled: false, blocking: false }
    { name: 'Indirect Attack', source: 'Prompt', enabled: true, blocking: false }
    { name: 'Indirect Attack', source: 'PostToolCall', enabled: true, blocking: false }
    { name: 'Protected Material Text', source: 'Completion', enabled: true, blocking: true }
    { name: 'Protected Material Code', source: 'Completion', enabled: true, blocking: false }
  ]
)

resource raiStrict 'Microsoft.CognitiveServices/accounts/raiPolicies@2026-03-01' = {
  parent: foundry
  name: 'strict'
  dependsOn: [appInsightsConnection]
  properties: {
    basePolicyName: 'Microsoft.DefaultV2'
    mode: 'Default'
    contentFilters: strictFilters
  }
}

resource raiMinimal 'Microsoft.CognitiveServices/accounts/raiPolicies@2026-03-01' = {
  parent: foundry
  name: 'minimal'
  dependsOn: [raiStrict]
  properties: {
    basePolicyName: 'Microsoft.DefaultV2'
    mode: 'Default'
    contentFilters: minimalFilters
  }
}

// ---------- Model deployments (targets under test) ----------

var modelDeployments = [
  { name: 'gpt-5.4-mini-default', model: 'gpt-5.4-mini', version: '2026-03-17', format: 'OpenAI', capacity: chatCapacity, raiPolicy: 'Microsoft.DefaultV2' }
  { name: 'gpt-5.4-mini-strict', model: 'gpt-5.4-mini', version: '2026-03-17', format: 'OpenAI', capacity: chatCapacity, raiPolicy: raiStrict.name }
  { name: 'gpt-5.4-mini-minimal', model: 'gpt-5.4-mini', version: '2026-03-17', format: 'OpenAI', capacity: chatCapacity, raiPolicy: raiMinimal.name }
  { name: 'gpt-oss-120b', model: 'gpt-oss-120b', version: '1', format: 'OpenAI-OSS', capacity: ossCapacity, raiPolicy: 'Microsoft.DefaultV2' }
  { name: 'text-embedding-3-small', model: 'text-embedding-3-small', version: '1', format: 'OpenAI', capacity: embeddingCapacity, raiPolicy: 'Microsoft.DefaultV2' }
]

// One deployment at a time: the account rejects concurrent deployment writes.
@batchSize(1)
resource deployments 'Microsoft.CognitiveServices/accounts/deployments@2025-09-01' = [
  for d in modelDeployments: {
    parent: foundry
    name: d.name
    sku: {
      name: 'DataZoneStandard'
      capacity: d.capacity
    }
    properties: {
      model: {
        format: d.format
        name: d.model
        version: d.version
      }
      raiPolicyName: d.raiPolicy
      versionUpgradeOption: d.format == 'OpenAI' ? 'NoAutoUpgrade' : null
    }
  }
]

// ---------- Retrieval, gateway, safety, secrets ----------

resource search 'Microsoft.Search/searchServices@2025-05-01' = {
  name: searchName
  location: searchLocation
  tags: tags
  sku: { name: 'basic' }
  identity: { type: 'SystemAssigned' }
  properties: {
    replicaCount: 1
    partitionCount: 1
    hostingMode: 'Default'
    semanticSearch: 'free'
    disableLocalAuth: true
    publicNetworkAccess: 'enabled'
  }
}

resource contentSafety 'Microsoft.CognitiveServices/accounts@2025-09-01' = {
  name: contentSafetyName
  location: location
  tags: tags
  kind: 'ContentSafety'
  sku: { name: 'S0' }
  properties: {
    customSubDomainName: contentSafetyName
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    // Public access off (many org policies enforce this); trusted Azure services (APIM's identity) still get through.
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
  }
}

resource apim 'Microsoft.ApiManagement/service@2024-05-01' = {
  name: apimName
  location: location
  tags: tags
  sku: {
    name: 'BasicV2'
    capacity: 1
  }
  identity: { type: 'SystemAssigned' }
  properties: {
    publisherEmail: publisherEmail
    publisherName: 'AI Red Teaming Demo'
  }
}

// ---------- Diagnostics (evidence trail) ----------

resource foundryDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: foundry
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

resource contentSafetyDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: contentSafety
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

resource apimDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: apim
  properties: {
    workspaceId: law.id
    logAnalyticsDestinationType: 'Dedicated'
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

// ---------- RBAC (keyless everywhere) ----------

// Presenter
resource presenterFoundryUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(foundry.id, presenterObjectId, roleIds.foundryUser)
  scope: foundry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.foundryUser)
    principalId: presenterObjectId
    principalType: 'User'
  }
}

resource presenterSearchData 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(search.id, presenterObjectId, roleIds.searchIndexDataContributor)
  scope: search
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.searchIndexDataContributor)
    principalId: presenterObjectId
    principalType: 'User'
  }
}

resource presenterContentSafety 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(contentSafety.id, presenterObjectId, roleIds.cognitiveServicesUser)
  scope: contentSafety
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.cognitiveServicesUser)
    principalId: presenterObjectId
    principalType: 'User'
  }
}

resource presenterKeyVault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, presenterObjectId, roleIds.keyVaultSecretsOfficer)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.keyVaultSecretsOfficer)
    principalId: presenterObjectId
    principalType: 'User'
  }
}

// Foundry account + project identities -> AI Search (agent AI Search tool, keyless)
resource foundrySearchData 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(search.id, foundry.id, roleIds.searchIndexDataContributor)
  scope: search
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.searchIndexDataContributor)
    principalId: foundry.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource foundrySearchService 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(search.id, foundry.id, roleIds.searchServiceContributor)
  scope: search
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.searchServiceContributor)
    principalId: foundry.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource projectSearchData 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(search.id, project.id, roleIds.searchIndexDataContributor)
  scope: search
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.searchIndexDataContributor)
    principalId: project.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource projectSearchService 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(search.id, project.id, roleIds.searchServiceContributor)
  scope: search
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.searchServiceContributor)
    principalId: project.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Project identity -> model deployments (cloud red-team / eval runs call targets as the project)
resource projectFoundryUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(foundry.id, project.id, roleIds.foundryUser)
  scope: foundry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.foundryUser)
    principalId: project.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// AI Search identity -> embeddings (index vectorizer, keyless)
resource searchOpenAIUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(foundry.id, search.id, roleIds.cognitiveServicesOpenAIUser)
  scope: foundry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.cognitiveServicesOpenAIUser)
    principalId: search.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// APIM identity -> Foundry models, Content Safety, Key Vault (gateway scenarios S2-S4)
resource apimOpenAIUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(foundry.id, apim.id, roleIds.cognitiveServicesOpenAIUser)
  scope: foundry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.cognitiveServicesOpenAIUser)
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apimContentSafety 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(contentSafety.id, apim.id, roleIds.cognitiveServicesUser)
  scope: contentSafety
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.cognitiveServicesUser)
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apimKeyVault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, apim.id, roleIds.keyVaultSecretsUser)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.keyVaultSecretsUser)
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------- Outputs (no secrets) ----------

output foundryAccountName string = foundry.name
output foundryEndpoint string = foundry.properties.endpoint
output openAiV1Endpoint string = 'https://${foundryName}.openai.azure.com/openai/v1/'
output openAiEndpoint string = 'https://${foundryName}.openai.azure.com'
output projectEndpoint string = 'https://${foundryName}.services.ai.azure.com/api/projects/${projectName}'
output projectPrincipalId string = project.identity.principalId
output searchConnectionId string = searchConnection.id
output searchConnectionName string = searchConnection.name
output searchEndpoint string = 'https://${search.name}.search.windows.net'
output contentSafetyName string = contentSafety.name
output contentSafetyEndpoint string = contentSafety.properties.endpoint
output keyVaultUri string = keyVault.properties.vaultUri
output apimName string = apim.name
output apimGatewayUrl string = apim.properties.gatewayUrl
output appInsightsName string = appInsights.name
output logAnalyticsWorkspaceId string = law.id
output deploymentNames array = [for d in modelDeployments: d.name]
