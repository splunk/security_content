---
title: "DarkCrystal RAT"
last_modified_at: 2022-07-26
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command & Control
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the DcRat malware including ddos, spawning more process, botnet c2 communication, defense evasion and etc. The DcRat malware is known commercial backdoor that was first released in 2018. This tool was sold in underground forum and known to be one of the cheapest commercial RATs. DcRat is modular and bespoke plugin framework make it a very flexible option, helpful for a range of nefearious uses.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 639e6006-0885-4847-9394-ddc2902629bf

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading)| TTP |
| [Malicious PowerShell Process - Encoded Command](/endpoint/malicious_powershell_process_-_encoded_command/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information)| Hunting |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/malicious_powershell_process_-_execution_policy_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Product Spawn CMD Process](/endpoint/office_product_spawn_cmd_process/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Windows Command Shell DCRat ForkBomb Payload](/endpoint/windows_command_shell_dcrat_forkbomb_payload/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [Windows Gather Victim Network Info Through Ip Check Web Services](/endpoint/windows_gather_victim_network_info_through_ip_check_web_services/) | [IP Addresses](/tags/#ip-addresses), [Gather Victim Network Information](/tags/#gather-victim-network-information)| Hunting |
| [Windows High File Deletion Frequency](/endpoint/windows_high_file_deletion_frequency/) | [Data Destruction](/tags/#data-destruction)| Anomaly |
| [Windows System LogOff Commandline](/endpoint/windows_system_logoff_commandline/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot)| Anomaly |
| [Windows System Reboot CommandLine](/endpoint/windows_system_reboot_commandline/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot)| Anomaly |
| [Windows System Shutdown CommandLine](/endpoint/windows_system_shutdown_commandline/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot)| Anomaly |
| [Windows System Time Discovery W32tm Delay](/endpoint/windows_system_time_discovery_w32tm_delay/) | [System Time Discovery](/tags/#system-time-discovery)| Anomaly |
| [Winword Spawning Cmd](/endpoint/winword_spawning_cmd/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Winword Spawning PowerShell](/endpoint/winword_spawning_powershell/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |

#### Reference

* [https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor](https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/darkcrystal_rat.yml) \| *version*: **1**