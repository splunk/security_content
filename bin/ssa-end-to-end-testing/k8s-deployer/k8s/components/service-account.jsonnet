
local params = import '../params.libsonnet';

[
  {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      name: params.components.serviceAccountName,
    },
  },
]
