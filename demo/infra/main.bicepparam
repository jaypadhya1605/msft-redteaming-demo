using './main.bicep'

// Red Teaming Agent cloud runs: check the docs for currently supported regions.
param location = 'eastus2'
// AI Search can live in another region if capacity is short; the agent tool works cross-region.
param searchLocation = 'eastus2'
param baseName = 'redteam'
// Short unique suffix for globally unique names (Foundry subdomain, Key Vault, APIM, Search).
param nameSuffix = '<unique-suffix>'
param projectName = 'redteam-demo'
// Your Entra object ID in the subscription's tenant: az ad signed-in-user show --query id -o tsv
param presenterObjectId = '<your-entra-object-id>'
param publisherEmail = '<publisher-email>'
param chatCapacity = 100
param ossCapacity = 100
param embeddingCapacity = 50
