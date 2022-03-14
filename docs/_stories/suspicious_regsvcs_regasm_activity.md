---
title: "Suspicious Regsvcs Regasm Activity"
last_modified_at: 2021-02-11
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk
- **ID**: 2cdf33a0-4805-4b61-b025-59c20f418fbe

#### Narrative

 Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. The following queries assist with detecting suspicious and malicious usage of Regasm.exe and Regsvcs.exe. Upon reviewing usage of Regasm.exe Regsvcs.exe, review file modification events for possible script code written. Review parallel process events for csc.exe being utilized to compile script code.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Regasm Spawning a Process](/endpoint/detect_regasm_spawning_a_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regasm with Network Connection](/endpoint/detect_regasm_with_network_connection/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regasm with no Command Line Arguments](/endpoint/detect_regasm_with_no_command_line_arguments/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvcs Spawning a Process](/endpoint/detect_regsvcs_spawning_a_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvcs with Network Connection](/endpoint/detect_regsvcs_with_network_connection/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvcs with No Command Line Arguments](/endpoint/detect_regsvcs_with_no_command_line_arguments/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md)
* [https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_regsvcs_regasm_activity.yml) \| *version*: **1**