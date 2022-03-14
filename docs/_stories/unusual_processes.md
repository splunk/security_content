---
title: "Unusual Processes"
last_modified_at: 2020-02-04
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
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: Bhavin Patel, Splunk
- **ID**: f4368e3f-d59f-4192-84f6-748ac5a3ddb6

#### Narrative

Being able to profile a host's processes within your environment can help you more quickly identify processes that seem out of place when compared to the rest of the population of hosts or asset types.\
This Analytic Story lets you identify processes that are either a) not typically seen running or b) have some sort of suspicious command-line arguments associated with them. This Analytic Story will also help you identify the user running these processes and the associated process activity on the host.\
In the event an unusual process is identified, it is imperative to better understand how that process was able to execute on the host, when it first executed, and whether other hosts are affected. This extra information may provide clues that can help the analyst further investigate any suspicious activity.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Uncommon Processes On Endpoint](/deprecated/uncommon_processes_on_endpoint/) | [Malicious File](/tags/#malicious-file)| Hunting |
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning)| TTP |
| [Detect processes used for System Network Configuration Discovery](/endpoint/detect_processes_used_for_system_network_configuration_discovery/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery)| TTP |
| [Rundll32 Shimcache Flush](/endpoint/rundll32_shimcache_flush/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious Copy on System32](/endpoint/suspicious_copy_on_system32/) | [Rename System Utilities](/tags/#rename-system-utilities), [Masquerading](/tags/#masquerading)| TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities)| TTP |
| [Verclsid CLSID Execution](/endpoint/verclsid_clsid_execution/) | [Verclsid](/tags/#verclsid), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| Hunting |
| [Windows DotNet Binary in Non Standard Path](/endpoint/windows_dotnet_binary_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows NirSoft AdvancedRun](/endpoint/windows_nirsoft_advancedrun/) | [Tool](/tags/#tool)| TTP |
| [Windows Remote Assistance Spawning Process](/endpoint/windows_remote_assistance_spawning_process/) | [Process Injection](/tags/#process-injection)| TTP |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/wscript_or_cscript_suspicious_child_process/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation)| TTP |
| [Detect Rare Executables](/endpoint/detect_rare_executables/) | None| Anomaly |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None| Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None| Anomaly |
| [WinRM Spawning a Process](/endpoint/winrm_spawning_a_process/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html](https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html)
* [https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf](https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf)
* [https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262](https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/unusual_processes.yml) \| *version*: **2**