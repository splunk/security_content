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

#### Description

Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

- **ID**: f4368e3f-d59f-4192-84f6-748ac5a3ddb6
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | None | TTP |
| [Credential Extraction indicative of FGDump and CacheDump with s option](/endpoint/credential_extraction_indicative_of_fgdump_and_cachedump_with_s_option/) | None | TTP |
| [Credential Extraction indicative of FGDump and CacheDump with v option](/endpoint/credential_extraction_indicative_of_fgdump_and_cachedump_with_v_option/) | None | TTP |
| [Credential Extraction indicative of use of Mimikatz modules](/endpoint/credential_extraction_indicative_of_use_of_mimikatz_modules/) | None | TTP |
| [Credential Extraction native Microsoft debuggers peek into the kernel](/endpoint/credential_extraction_native_microsoft_debuggers_peek_into_the_kernel/) | None | TTP |
| [Credential Extraction native Microsoft debuggers via z command line option](/endpoint/credential_extraction_native_microsoft_debuggers_via_z_command_line_option/) | None | TTP |
| [Detect Rare Executables](/endpoint/detect_rare_executables/) | None | Anomaly |
| [Detect processes used for System Network Configuration Discovery](/endpoint/detect_processes_used_for_system_network_configuration_discovery/) | None | TTP |
| [First time seen command line argument](/endpoint/first_time_seen_command_line_argument/) | None | Anomaly |
| [More than usual number of LOLBAS applications in short time period](/endpoint/more_than_usual_number_of_lolbas_applications_in_short_time_period/) | None | Anomaly |
| [Rare Parent-Child Process Relationship](/endpoint/rare_parent-child_process_relationship/) | None | Anomaly |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | None | TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | None | TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None | Anomaly |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None | Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None | Anomaly |
| [WinRM Spawning a Process](/endpoint/winrm_spawning_a_process/) | None | TTP |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html](https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html)
* [https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf](https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf)
* [https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262](https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/unusual_processes.yml) | _version_: **2**