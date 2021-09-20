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

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Child Processes of Spoolsv exe](/endpoint/child_processes_of_spoolsv_exe/) | None | TTP |
| [Illegal Privilege Elevation via Mimikatz modules](/endpoint/illegal_privilege_elevation_via_mimikatz_modules/) | None | TTP |
| [Overwriting Accessibility Binaries](/endpoint/overwriting_accessibility_binaries/) | None | TTP |
| [Probing Access with Stolen Credentials via PowerSploit modules](/endpoint/probing_access_with_stolen_credentials_via_powersploit_modules/) | None | TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



_version_: 2