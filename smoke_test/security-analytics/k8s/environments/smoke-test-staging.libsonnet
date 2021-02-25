
// this file has the param overrides for the default environment
local base = import './base.libsonnet';

base {
  components +: {
    smokeTestImage: 'docker-test.repo.splunkdev.net/user-icorrales/security-content-test',
    serviceAccountName: "sa-tr-staging",
    tenant: 'research',
    dspEnv: 'staging',
  }
}
