
// this file has the param overrides for the default environment
local base = import './base.libsonnet';

base {
  components +: {
    serviceAccountName: "sa-tr-staging",
    vaultReadPath: 'scpauth-app-stage1/token/threat-research-test.app-stage1',
    tenant: 'research',
    dspEnv: 'staging',
  }
}
