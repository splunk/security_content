---
title: "Double Zero Destructor"
last_modified_at: 2022-03-25
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

Double Zero Destructor is a destructive payload that enumerates Domain Controllers and executes killswitch if detected. Overwrites files with Zero blocks or using MS Windows API calls such as NtFileOpen, NtFSControlFile. This payload also deletes registry hives HKCU,HKLM, HKU, HKLM BCD.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-25
- **Author**: Teoderick Contreras, Rod Soto, Splunk
- **ID**: f56e8c00-3224-4955-9a6e-924ec7da1df7

#### Narrative

Double zero destructor enumerates domain controllers, delete registry hives and overwrites files using zero blocks and API calls.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading)| TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Windows Deleted Registry By A Non Critical Process File Path](/endpoint/windows_deleted_registry_by_a_non_critical_process_file_path/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Terminating Lsass Process](/endpoint/windows_terminating_lsass_process/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| Anomaly |

#### Reference

* [https://cert.gov.ua/article/38088](https://cert.gov.ua/article/38088)
* [https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html](https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/double_zero_destructor.yml) \| *version*: **1**