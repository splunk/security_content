---
title: "Suspicious Windows Registry Activities"
last_modified_at: 2018-05-31
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

Monitor and detect registry changes initiated from remote locations, which can be a sign that an attacker has infiltrated your system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk
- **ID**: 2b1800dd-92f9-47dd-a981-fdf1351e5d55

#### Narrative

Attackers are developing increasingly sophisticated techniques for hijacking target servers, while evading detection. One such technique that has become progressively more common is registry modification.\
 The registry is a key component of the Windows operating system. It has a hierarchical database called "registry" that contains settings, options, and values for executables. Once the threat actor gains access to a machine, they can use reg.exe to modify their account to obtain administrator-level privileges, maintain persistence, and move laterally within the environment.\
 The searches in this story are designed to help you detect behaviors associated with manipulation of the Windows registry.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Reg exe used to hide files directories via registry keys](/deprecated/reg_exe_used_to_hide_files_directories_via_registry_keys/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories)| TTP |
| [Remote Registry Key modifications](/deprecated/remote_registry_key_modifications/) | None| TTP |
| [Suspicious Changes to File Associations](/deprecated/suspicious_changes_to_file_associations/) | [Change Default File Association](/tags/#change-default-file-association)| TTP |
| [Disable UAC Remote Restriction](/endpoint/disable_uac_remote_restriction/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | [Port Monitors](/tags/#port-monitors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Windows Service Creation Using Registry Entry](/endpoint/windows_service_creation_using_registry_entry/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness)| TTP |

#### Reference

* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)
* [https://attack.mitre.org/wiki/Technique/T1112](https://attack.mitre.org/wiki/Technique/T1112)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_windows_registry_activities.yml) \| *version*: **1**