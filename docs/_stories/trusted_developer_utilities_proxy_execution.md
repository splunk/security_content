---
title: "Trusted Developer Utilities Proxy Execution"
last_modified_at: 2021-01-12
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect behaviors used by attackers who leverage trusted developer utilities to execute malicious code.

- **ID**: 270a67a6-55d8-11eb-ae93-0242ac130002
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-12
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | None | TTP |
| [Suspicious microsoft workflow compiler usage](/endpoint/suspicious_microsoft_workflow_compiler_usage/) | None | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/](https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/trusted_developer_utilities_proxy_execution.yml) \| *version*: **1**