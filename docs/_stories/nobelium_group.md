---
title: "NOBELIUM Group"
last_modified_at: 2020-12-14
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Sunburst is a trojanized updates to SolarWinds Orion IT monitoring and management software. It was discovered by FireEye in December 2020. The actors behind this campaign gained access to numerous public and private organizations around the world.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2020-12-14
- **Author**: Patrick Bareiss, Michael Haag, Splunk
- **ID**: 758196b5-2e21-424f-a50c-6e421ce926c2

#### Narrative

This Analytic Story supports you to detect Tactics, Techniques and Procedures (TTPs) of the NOBELIUM Group. The threat actor behind sunburst compromised the SolarWinds.Orion.Core.BusinessLayer.dll, is a SolarWinds digitally-signed component of the Orion software framework that contains a backdoor that communicates via HTTP to third party servers. The detections in this Analytic Story are focusing on the dll loading events, file create events and network events to detect This malware.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/anomalous_usage_of_7zip/) | [Archive via Utility](/tags/#archive-via-utility), [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service), [Process Injection](/tags/#process-injection), [File Transfer Protocols](/tags/#file-transfer-protocols), [Regsvr32](/tags/#regsvr32), [Mshta](/tags/#mshta), [Service Execution](/tags/#service-execution), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Rundll32](/tags/#rundll32), [Scheduled Task](/tags/#scheduled-task), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Exploitation for Client Execution](/tags/#exploitation-for-client-execution), [Web Shell](/tags/#web-shell), [MSBuild](/tags/#msbuild), [Rename System Utilities](/tags/#rename-system-utilities), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Web Protocols](/tags/#web-protocols), [Remote System Discovery](/tags/#remote-system-discovery) | Anomaly |
| [Detect Outbound SMB Traffic](/network/detect_outbound_smb_traffic/) | [File Transfer Protocols](/tags/#file-transfer-protocols) | TTP |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Rename System Utilities](/tags/#rename-system-utilities) | Hunting |
| [Detect Rundll32 Inline HTA Execution](/endpoint/detect_rundll32_inline_hta_execution/) | [Mshta](/tags/#mshta) | TTP |
| [First Time Seen Running Windows Service](/endpoint/first_time_seen_running_windows_service/) | [Service Execution](/tags/#service-execution), [Process Injection](/tags/#process-injection), [Native API](/tags/#native-api), [System Services](/tags/#system-services), [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Windows Service](/tags/#windows-service) | Anomaly |
| [Malicious PowerShell Process - Encoded Command](/endpoint/malicious_powershell_process_-_encoded_command/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | Hunting |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service) | TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Schtasks scheduling job on remote system](/endpoint/schtasks_scheduling_job_on_remote_system/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Sunburst Correlation DLL and Network Event](/endpoint/sunburst_correlation_dll_and_network_event/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution) | TTP |
| [Supernova Webshell](/web/supernova_webshell/) | [Web Shell](/tags/#web-shell) | TTP |
| [TOR Traffic](/network/tor_traffic/) | [Web Protocols](/tags/#web-protocols) | TTP |
| [Windows AdFind Exe](/endpoint/windows_adfind_exe/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |

#### Reference

* [https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
* [https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/nobelium_group.yml) \| *version*: **2**