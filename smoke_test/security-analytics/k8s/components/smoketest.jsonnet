
local params = import '../params.libsonnet';

[
  {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: {
      name: 'ssa-smoke-test',
    },
    spec: {
        activeDeadlineSeconds: 100,
        template: {
            metadata: {
                annotations: {
                    'splunk8s.io.vault/init-container': 'true',
                },
            },
            spec: {
              serviceAccountName: params.components.serviceAccountName,
              restartPolicy: 'Never',
              containers: [
                {
                  name: 'ssa-smoke-test',
                  image: params.components.smokeTestImage,
                  imagePullPolicy: 'Always',
                  env: [
                    {
                        "name": 'SCBRANCH',
                        "value": std.extVar('SCBRANCH')
                    },
                    {
                        "name": 'ENV',
                        "value": std.extVar('qbec.io/env')
                    },
                  ],
                  resources: {
                    limits: {
                        cpu: '1',
                        memory: '1000Mi'
                    },
                    requests: {
                        cpu: '800m',
                        memory: '750Mi'
                    },
                    command: ['/bin/bash', '-c'],
                    args: ['cd /smoketest && ./smoketest.sh']
                  },
                },
              ],
            },
        },
    },


  },
]
