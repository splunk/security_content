---
title: "Trickbot"
last_modified_at: 2021-04-20
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the trickbot banking trojan, including looking for file writes associated with its payload, process injection, shellcode execution and data collection even in LDAP environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-20
- **Author**: Rod Soto, Teoderick Contreras, Splunk
- **ID**: 16f93769-8342-44c0-9b1d-f131937cce8e

#### Narrative

trickbot banking trojan campaigns targeting banks and other vertical sectors.This malware is known in Microsoft Windows OS where target security Microsoft Defender to prevent its detection and removal. steal Verizon credentials and targeting banks using its multi component modules that collect and exfiltrate data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Account Discovery With Net App](/endpoint/account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Process Injection](/tags/#process-injection), [Malicious File](/tags/#malicious-file), [Bypass User Account Control](/tags/#bypass-user-account-control), [Modify Registry](/tags/#modify-registry), [Archive via Utility](/tags/#archive-via-utility), [Mshta](/tags/#mshta), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Spearphishing Attachment](/tags/#spearphishing-attachment), [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Rundll32](/tags/#rundll32), [Scheduled Task/Job](/tags/#scheduled-task/job), [Data from Local System](/tags/#data-from-local-system), [Regsvr32](/tags/#regsvr32), [IP Addresses](/tags/#ip-addresses), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Scheduled Task](/tags/#scheduled-task), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | [Process Injection](/tags/#process-injection) | TTP |
| [Mshta spawning Rundll32 OR Regsvr32 Process](/endpoint/mshta_spawning_rundll32_or_regsvr32_process/) | [Mshta](/tags/#mshta) | TTP |
| [Office Application Spawn rundll32 process](/endpoint/office_application_spawn_rundll32_process/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawn CMD Process](/endpoint/office_product_spawn_cmd_process/) | [Mshta](/tags/#mshta) | TTP |
| [Powershell Remote Thread To Known Windows Process](/endpoint/powershell_remote_thread_to_known_windows_process/) | [Process Injection](/tags/#process-injection) | TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | [Rundll32](/tags/#rundll32) | TTP |
| [Trickbot Named Pipe](/endpoint/trickbot_named_pipe/) | [Process Injection](/tags/#process-injection) | TTP |
| [Wermgr Process Connecting To IP Check Web Services](/endpoint/wermgr_process_connecting_to_ip_check_web_services/) | [IP Addresses](/tags/#ip-addresses) | TTP |
| [Wermgr Process Create Executable File](/endpoint/wermgr_process_create_executable_file/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | TTP |
| [Wermgr Process Spawned CMD Or Powershell Process](/endpoint/wermgr_process_spawned_cmd_or_powershell_process/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [Write Executable in SMB Share](/endpoint/write_executable_in_smb_share/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |

#### Reference

* [https://en.wikipedia.org/wiki/Trickbot](https://en.wikipedia.org/wiki/Trickbot)
* [https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/](https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/trickbot.yml) \| *version*: **1**