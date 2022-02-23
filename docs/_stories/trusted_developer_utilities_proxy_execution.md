---
title: "Trusted Developer Utilities Proxy Execution"
last_modified_at: 2021-01-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor and detect behaviors used by attackers who leverage trusted developer utilities to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-12
- **Author**: Michael Haag, Splunk
- **ID**: 270a67a6-55d8-11eb-ae93-0242ac130002

#### Narrative

Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.\
The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging microsoft.workflow.compiler.exe to execute malicious code.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities)| Hunting |
| [Suspicious microsoft workflow compiler usage](/endpoint/suspicious_microsoft_workflow_compiler_usage/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/](https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/trusted_developer_utilities_proxy_execution.yml) \| *version*: **1**