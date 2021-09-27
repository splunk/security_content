---
title: "Windows Privilege Escalation"
last_modified_at: 2020-02-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for and investigate activities that may be associated with a Windows privilege-escalation attack, including unusual processes running on endpoints, modified registry keys, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk
- **ID**: 644e22d3-598a-429c-a007-16fdb802cae5

#### Narrative

Privilege escalation is a "land-and-expand" technique, wherein an adversary gains an initial foothold on a host and then exploits its weaknesses to increase his privileges. The motivation is simple: certain actions on a Windows machine--such as installing software--may require higher-level privileges than those the attacker initially acquired. By increasing his privilege level, the attacker can gain the control required to carry out his malicious ends. This Analytic Story provides searches to detect and investigate behaviors that attackers may use to elevate their privileges in your environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Child Processes of Spoolsv exe](/endpoint/child_processes_of_spoolsv_exe/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Access Token Manipulation](/tags/#access-token-manipulation), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Accessibility Features](/tags/#accessibility-features), [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation), [Image File Execution Options Injection](/tags/#image-file-execution-options-injection) | TTP |
| [Illegal Privilege Elevation via Mimikatz modules](/endpoint/illegal_privilege_elevation_via_mimikatz_modules/) | [Access Token Manipulation](/tags/#access-token-manipulation), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Overwriting Accessibility Binaries](/endpoint/overwriting_accessibility_binaries/) | [Accessibility Features](/tags/#accessibility-features) | TTP |
| [Probing Access with Stolen Credentials via PowerSploit modules](/endpoint/probing_access_with_stolen_credentials_via_powersploit_modules/) | [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation) | TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection) | TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_privilege_escalation.yml) \| *version*: **2**