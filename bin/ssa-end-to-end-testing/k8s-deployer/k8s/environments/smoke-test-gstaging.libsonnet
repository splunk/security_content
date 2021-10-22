
// this file has the param overrides for the default environment
local base = import './base.libsonnet';

base {
  components +: {
    serviceAccountName: "sa-tr-staging",
    vaultReadPath: 'scpauth-kube-wicket-iad10/token/threat-research-test.app-gstage1',
    tenant: 'research',
    dspEnv: 'staging',
  }
}
