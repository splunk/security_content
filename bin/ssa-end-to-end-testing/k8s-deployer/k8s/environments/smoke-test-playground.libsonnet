
// this file has the param overrides for the default environment
local base = import './base.libsonnet';

base {
  components +: {
    serviceAccountName: "sa-tr-playground",
    vaultReadPath: 'scpauth-app-play1/token/threat-research-test.app-play1',
    tenant: 'research2',
    dspEnv: 'playground',
  }
}
