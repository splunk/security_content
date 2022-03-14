---
title: "IcedID"
last_modified_at: 2021-07-29
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the IcedID banking trojan, including looking for file writes associated with its payload, process injection, shellcode execution and data collection.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1d2cc747-63d7-49a9-abb8-93aa36305603

#### Narrative

IcedId banking trojan campaigns targeting banks and other vertical sectors.This malware is known in Microsoft Windows OS targetting browser such as firefox and chrom to steal banking information. It is also known to its unique payload downloaded in C2 where it can be a .png file that hides the core shellcode bot using steganography technique or gzip dat file that contains "license.dat" which is the actual core icedid bot.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Account Discovery With Net App](/endpoint/account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [CHCP Command Execution](/endpoint/chcp_command_execution/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Create Remote Thread In Shell Application](/endpoint/create_remote_thread_in_shell_application/) | [Process Injection](/tags/#process-injection)| TTP |
| [Disable Schedule Task](/endpoint/disable_schedule_task/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Drop IcedID License dat](/endpoint/drop_icedid_license_dat/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file)| Hunting |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | [Modify Registry](/tags/#modify-registry), [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [IcedID Exfiltrated Archived File Creation](/endpoint/icedid_exfiltrated_archived_file_creation/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data)| Hunting |
| [Mshta spawning Rundll32 OR Regsvr32 Process](/endpoint/mshta_spawning_rundll32_or_regsvr32_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Office Application Spawn Regsvr32 process](/endpoint/office_application_spawn_regsvr32_process/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Application Spawn rundll32 process](/endpoint/office_application_spawn_rundll32_process/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Product Spawning MSHTA](/endpoint/office_product_spawning_mshta/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Regsvr32 with Known Silent Switch Cmdline](/endpoint/regsvr32_with_known_silent_switch_cmdline/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Rundll32 Create Remote Thread To A Process](/endpoint/rundll32_create_remote_thread_to_a_process/) | [Process Injection](/tags/#process-injection)| TTP |
| [Rundll32 CreateRemoteThread In Browser](/endpoint/rundll32_createremotethread_in_browser/) | [Process Injection](/tags/#process-injection)| TTP |
| [Rundll32 DNSQuery](/endpoint/rundll32_dnsquery/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Rundll32 Process Creating Exe Dll Files](/endpoint/rundll32_process_creating_exe_dll_files/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Sqlite Module In Temp Folder](/endpoint/sqlite_module_in_temp_folder/) | [Data from Local System](/tags/#data-from-local-system)| TTP |
| [Suspicious IcedID Rundll32 Cmdline](/endpoint/suspicious_icedid_rundll32_cmdline/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious Rundll32 PluginInit](/endpoint/suspicious_rundll32_plugininit/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/winevent_windows_task_scheduler_event_action_started/) | [Scheduled Task](/tags/#scheduled-task)| Hunting |

#### Reference

* [https://threatpost.com/icedid-banking-trojan-surges-emotet/165314/](https://threatpost.com/icedid-banking-trojan-surges-emotet/165314/)
* [https://app.any.run/tasks/48414a33-3d66-4a46-afe5-c2003bb55ccf/](https://app.any.run/tasks/48414a33-3d66-4a46-afe5-c2003bb55ccf/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/icedid.yml) \| *version*: **1**