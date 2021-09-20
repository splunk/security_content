---
title: "Suspicious Regsvcs Regasm Activity"
last_modified_at: 2021-02-11
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **ID**: 2cdf33a0-4805-4b61-b025-59c20f418fbe
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Regasm Spawning a Process](/endpoint/detect_regasm_spawning_a_process/) | None | TTP |
| [Detect Regasm with Network Connection](/endpoint/detect_regasm_with_network_connection/) | None | TTP |
| [Detect Regasm with no Command Line Arguments](/endpoint/detect_regasm_with_no_command_line_arguments/) | None | TTP |
| [Detect Regsvcs Spawning a Process](/endpoint/detect_regsvcs_spawning_a_process/) | None | TTP |
| [Detect Regsvcs with Network Connection](/endpoint/detect_regsvcs_with_network_connection/) | None | TTP |
| [Detect Regsvcs with No Command Line Arguments](/endpoint/detect_regsvcs_with_no_command_line_arguments/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md)
* [https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)



_version_: 1