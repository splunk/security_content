---
title: "Windows Privilege Escalation"
last_modified_at: 2020-02-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
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
| [Uncommon Processes On Endpoint](/deprecated/uncommon_processes_on_endpoint/) | None| Hunting |
| [Active Setup Registry Autostart](/endpoint/active_setup_registry_autostart/) | None| TTP |
| [Change Default File Association](/endpoint/change_default_file_association/) | None| TTP |
| [ETW Registry Disabled](/endpoint/etw_registry_disabled/) | None| TTP |
| [Kerberoasting spn request with RC4 encryption](/endpoint/kerberoasting_spn_request_with_rc4_encryption/) | None| TTP |
| [Logon Script Event Trigger Execution](/endpoint/logon_script_event_trigger_execution/) | None| TTP |
| [MSI Module Loaded by Non-System Binary](/endpoint/msi_module_loaded_by_non-system_binary/) | None| Hunting |
| [Overwriting Accessibility Binaries](/endpoint/overwriting_accessibility_binaries/) | None| TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | None| TTP |
| [Runas Execution in CommandLine](/endpoint/runas_execution_in_commandline/) | None| Hunting |
| [Screensaver Event Trigger Execution](/endpoint/screensaver_event_trigger_execution/) | None| TTP |
| [Time Provider Persistence Registry](/endpoint/time_provider_persistence_registry/) | None| TTP |
| [Child Processes of Spoolsv exe](/endpoint/child_processes_of_spoolsv_exe/) | None| TTP |
| [Print Processor Registry Autostart](/endpoint/print_processor_registry_autostart/) | None| TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_privilege_escalation.yml) \| *version*: **2**