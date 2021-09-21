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

#### Description

Monitor for and investigate activities that may be associated with a Windows privilege-escalation attack, including unusual processes running on endpoints, modified registry keys, and more.

- **ID**: 644e22d3-598a-429c-a007-16fdb802cae5
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk

#### Narrative

Privilege escalation is a "land-and-expand" technique, wherein an adversary gains an initial foothold on a host and then exploits its weaknesses to increase his privileges. The motivation is simple: certain actions on a Windows machine--such as installing software--may require higher-level privileges than those the attacker initially acquired. By increasing his privilege level, the attacker can gain the control required to carry out his malicious ends. This Analytic Story provides searches to detect and investigate behaviors that attackers may use to elevate their privileges in your environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Child Processes of Spoolsv exe](/endpoint/child_processes_of_spoolsv_exe/) | None | TTP |
| [Illegal Privilege Elevation via Mimikatz modules](/endpoint/illegal_privilege_elevation_via_mimikatz_modules/) | None | TTP |
| [Overwriting Accessibility Binaries](/endpoint/overwriting_accessibility_binaries/) | None | TTP |
| [Probing Access with Stolen Credentials via PowerSploit modules](/endpoint/probing_access_with_stolen_credentials_via_powersploit_modules/) | None | TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | None | TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_privilege_escalation.yml) \| *version*: **2**