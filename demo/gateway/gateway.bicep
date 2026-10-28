// Gateway comparison routes on the API Management instance from main.bicep (runtime protection comparison).
//   S1 = Foundry Default.V2 guardrail, no gateway. A direct call to Foundry, so nothing to deploy here.
//   S2 = minimal guardrail, no gateway policy (exposure baseline).
//   S3 = minimal guardrail + llm-content-safety (Content Safety harm categories + Prompt Shields).
//   S4 = minimal guardrail + CrowdStrike AIDR policy. Template only; add it in a pilot with your own AIDR collector.
// Keyless: callers send an Entra token; APIM calls Foundry and Content Safety with its managed identity (roles granted in main.bicep).
// Deploy after main.bicep:
//   az deployment group create -g <resource-group> --subscription <sub-id> -f gateway.bicep -p gateway.bicepparam

targetScope = 'resourceGroup'

@description('Workload token used in resource names (same value as main.bicep).')
param baseName string = 'redteam'

@description('Suffix used in globally unique resource names (same value as main.bicep).')
param nameSuffix string

@description('Entra object IDs allowed to call the gateway routes, such as the presenter and a CI identity.')
param allowedCallerObjectIds array

@description('Foundry deployment behind S2 and S3. Both routes pin requests to it, so they differ only in gateway policy.')
param targetDeployment string = 'gpt-5.4-mini-minimal'

@description('Content Safety severity (0-7, EightSeverityLevels) at which S3 blocks Hate, SelfHarm, Sexual, or Violence. Lower blocks more.')
@minValue(0)
@maxValue(7)
param blockThreshold int = 4

var foundryName = 'fndry-${baseName}-${nameSuffix}'
var contentSafetyName = 'cs-${baseName}-${nameSuffix}'
var apimName = 'apim-${baseName}-${nameSuffix}'
var callerValues = join(map(allowedCallerObjectIds, id => '<value>${id}</value>'), '')

var s2Policy = replace(replace(replace(loadTextContent('policies/s2-no-policy.xml'), '{tenant-id}', tenant().tenantId), '{allowed-callers}', callerValues), '{target-deployment}', targetDeployment)
var s3Policy = replace(replace(replace(replace(loadTextContent('policies/s3-content-safety.xml'), '{tenant-id}', tenant().tenantId), '{allowed-callers}', callerValues), '{target-deployment}', targetDeployment), '{block-threshold}', string(blockThreshold))

var routes = [
  {
    name: 'llm-s2-no-policy'
    displayName: 'S2 - minimal guardrail, no gateway policy'
    path: 's2'
    policy: s2Policy
  }
  {
    name: 'llm-s3-content-safety'
    displayName: 'S3 - minimal guardrail + llm-content-safety'
    path: 's3'
    policy: s3Policy
  }
]

resource apim 'Microsoft.ApiManagement/service@2024-05-01' existing = {
  name: apimName
}

// llm-content-safety requires a backend that authenticates with managed identity. The property isn't in the
// published ARM schema yet (hence BCP037); see https://learn.microsoft.com/azure/api-management/llm-content-safety-policy#prerequisites
resource contentSafetyBackend 'Microsoft.ApiManagement/service/backends@2024-06-01-preview' = {
  parent: apim
  name: 'content-safety'
  properties: {
    description: 'Azure AI Content Safety, called by the S3 llm-content-safety policy'
    url: 'https://${contentSafetyName}.cognitiveservices.azure.com'
    protocol: 'http'
    credentials: {
      #disable-next-line BCP037
      managedIdentity: {
        resource: 'https://cognitiveservices.azure.com'
      }
    }
  }
}

resource apis 'Microsoft.ApiManagement/service/apis@2024-05-01' = [for r in routes: {
  parent: apim
  name: r.name
  properties: {
    displayName: r.displayName
    path: r.path
    protocols: ['https']
    serviceUrl: 'https://${foundryName}.openai.azure.com/openai/v1'
    subscriptionRequired: false
  }
}]

resource responsesOperations 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = [for (r, i) in routes: {
  parent: apis[i]
  name: 'create-response'
  properties: {
    displayName: 'Create response (OpenAI Responses API)'
    method: 'POST'
    urlTemplate: '/responses'
  }
}]

resource chatOperations 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = [for (r, i) in routes: {
  parent: apis[i]
  name: 'create-chat-completion'
  properties: {
    displayName: 'Create chat completion'
    method: 'POST'
    urlTemplate: '/chat/completions'
  }
}]

resource apiPolicies 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = [for (r, i) in routes: {
  parent: apis[i]
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: r.policy
  }
  dependsOn: [
    contentSafetyBackend
  ]
}]

output s1ResponsesUrl string = 'https://${foundryName}.openai.azure.com/openai/v1/responses'
output s2ResponsesUrl string = '${apim.properties.gatewayUrl}/s2/responses'
output s3ResponsesUrl string = '${apim.properties.gatewayUrl}/s3/responses'
