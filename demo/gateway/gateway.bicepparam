using 'gateway.bicep'

// Must match main.bicepparam.
param baseName = 'redteam'
param nameSuffix = '<unique-suffix>'
// Callers allowed through the gateway routes (same as presenterObjectId in main.bicepparam). Add a CI identity for pipeline runs.
param allowedCallerObjectIds = [
  '<your-entra-object-id>'
]
param targetDeployment = 'gpt-5.4-mini-minimal'
param blockThreshold = 4
