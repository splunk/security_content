---
title: "Trickbot"
last_modified_at: 2021-04-20
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
  - Installation
  - Reconnaissance
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
| [Account Discovery With Net App](/endpoint/account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | [Process Injection](/tags/#process-injection)| TTP |
| [Executable File Written in Administrative SMB Share](/endpoint/executable_file_written_in_administrative_smb_share/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Mshta spawning Rundll32 OR Regsvr32 Process](/endpoint/mshta_spawning_rundll32_or_regsvr32_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Office Application Spawn rundll32 process](/endpoint/office_application_spawn_rundll32_process/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Product Spawn CMD Process](/endpoint/office_product_spawn_cmd_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Powershell Remote Thread To Known Windows Process](/endpoint/powershell_remote_thread_to_known_windows_process/) | [Process Injection](/tags/#process-injection)| TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Trickbot Named Pipe](/endpoint/trickbot_named_pipe/) | [Process Injection](/tags/#process-injection)| TTP |
| [Wermgr Process Connecting To IP Check Web Services](/endpoint/wermgr_process_connecting_to_ip_check_web_services/) | [Gather Victim Network Information](/tags/#gather-victim-network-information), [IP Addresses](/tags/#ip-addresses)| TTP |
| [Wermgr Process Create Executable File](/endpoint/wermgr_process_create_executable_file/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information)| TTP |
| [Wermgr Process Spawned CMD Or Powershell Process](/endpoint/wermgr_process_spawned_cmd_or_powershell_process/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |

#### Reference

* [https://en.wikipedia.org/wiki/Trickbot](https://en.wikipedia.org/wiki/Trickbot)
* [https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/](https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/trickbot.yml) \| *version*: **1**