---
title: "Unusual Processes"
last_modified_at: 2020-02-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

- **ID**: f4368e3f-d59f-4192-84f6-748ac5a3ddb6
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: Bhavin Patel, Splunk

#### Narrative

Being able to profile a host's processes within your environment can help you more quickly identify processes that seem out of place when compared to the rest of the population of hosts or asset types.\
This Analytic Story lets you identify processes that are either a) not typically seen running or b) have some sort of suspicious command-line arguments associated with them. This Analytic Story will also help you identify the user running these processes and the associated process activity on the host.\
In the event an unusual process is identified, it is imperative to better understand how that process was able to execute on the host, when it first executed, and whether other hosts are affected. This extra information may provide clues that can help the analyst further investigate any suspicious activity.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Active Scanning](/tags/#active-scanning), [OS Credential Dumping](/tags/#os-credential-dumping), [Service Stop](/tags/#service-stop), [Malicious File](/tags/#malicious-file), [Data Destruction](/tags/#data-destruction), [Account Access Removal](/tags/#account-access-removal), [Inhibit System Recovery](/tags/#inhibit-system-recovery), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Service Execution](/tags/#service-execution), [System Information Discovery](/tags/#system-information-discovery), [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Account Discovery](/tags/#account-discovery), [Masquerading](/tags/#masquerading), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Regsvr32](/tags/#regsvr32), [Indirect Command Execution](/tags/#indirect-command-execution), [Scheduled Task/Job](/tags/#scheduled-task/job), [Exploitation for Client Execution](/tags/#exploitation-for-client-execution), [Software Deployment Tools](/tags/#software-deployment-tools), [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Rundll32](/tags/#rundll32), [Data Encrypted for Impact](/tags/#data-encrypted-for-impact), [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Rename System Utilities](/tags/#rename-system-utilities), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Credential Extraction indicative of FGDump and CacheDump with s option](/endpoint/credential_extraction_indicative_of_fgdump_and_cachedump_with_s_option/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Credential Extraction indicative of FGDump and CacheDump with v option](/endpoint/credential_extraction_indicative_of_fgdump_and_cachedump_with_v_option/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Credential Extraction indicative of use of Mimikatz modules](/endpoint/credential_extraction_indicative_of_use_of_mimikatz_modules/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Credential Extraction native Microsoft debuggers peek into the kernel](/endpoint/credential_extraction_native_microsoft_debuggers_peek_into_the_kernel/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Credential Extraction native Microsoft debuggers via z command line option](/endpoint/credential_extraction_native_microsoft_debuggers_via_z_command_line_option/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Detect Rare Executables](/endpoint/detect_rare_executables/) |  | Anomaly |
| [Detect processes used for System Network Configuration Discovery](/endpoint/detect_processes_used_for_system_network_configuration_discovery/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery) | TTP |
| [First time seen command line argument](/endpoint/first_time_seen_command_line_argument/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Regsvr32](/tags/#regsvr32), [Indirect Command Execution](/tags/#indirect-command-execution) | Anomaly |
| [More than usual number of LOLBAS applications in short time period](/endpoint/more_than_usual_number_of_lolbas_applications_in_short_time_period/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Rare Parent-Child Process Relationship](/endpoint/rare_parent-child_process_relationship/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Scheduled Task/Job](/tags/#scheduled-task/job), [Software Deployment Tools](/tags/#software-deployment-tools) | Anomaly |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | [Rundll32](/tags/#rundll32) | TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) |  | Anomaly |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) |  | Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) |  | Anomaly |
| [WinRM Spawning a Process](/endpoint/winrm_spawning_a_process/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html](https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html)
* [https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf](https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf)
* [https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262](https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/unusual_processes.yml) \| *version*: **2**