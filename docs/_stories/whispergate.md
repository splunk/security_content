---
title: "WhisperGate"
last_modified_at: 2022-01-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command and Control
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the destructive malware targeting Ukrainian organizations also known as "WhisperGate". This analytic story looks for suspicious process execution, command-line activity, downloads, DNS queries and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0150e6e5-3171-442e-83f8-1ccd8599569b

#### Narrative

WhisperGate/DEV-0586 is destructive malware operation found by MSTIC (Microsoft Threat Inteligence Center) targeting multiple organizations in Ukraine. This operation campaign consist of several malware component like the downloader that abuses discord platform, overwrite or destroy master boot record (MBR) of the targeted host, wiper and also windows defender evasion techniques.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add or Set Windows Defender Exclusion](/endpoint/add_or_set_windows_defender_exclusion/) | None| TTP |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | None| TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | None| Hunting |
| [Excessive File Deletion In WinDefender Folder](/endpoint/excessive_file_deletion_in_windefender_folder/) | None| TTP |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | None| TTP |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/impacket_lateral_movement_commandline_parameters/) | None| TTP |
| [Malicious PowerShell Process - Encoded Command](/endpoint/malicious_powershell_process_-_encoded_command/) | None| Hunting |
| [Ping Sleep Batch Command](/endpoint/ping_sleep_batch_command/) | None| Anomaly |
| [Powershell Remove Windows Defender Directory](/endpoint/powershell_remove_windows_defender_directory/) | None| TTP |
| [Powershell Windows Defender Exclusion Commands](/endpoint/powershell_windows_defender_exclusion_commands/) | None| TTP |
| [Process Deleting Its Process File Path](/endpoint/process_deleting_its_process_file_path/) | None| TTP |
| [Suspicious Process DNS Query Known Abuse Web Services](/endpoint/suspicious_process_dns_query_known_abuse_web_services/) | None| TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | None| TTP |
| [Suspicious Process With Discord DNS Query](/endpoint/suspicious_process_with_discord_dns_query/) | None| Anomaly |
| [Windows DotNet Binary in Non Standard Path](/endpoint/windows_dotnet_binary_in_non_standard_path/) | None| TTP |
| [Windows High File Deletion Frequency](/endpoint/windows_high_file_deletion_frequency/) | None| Anomaly |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | None| TTP |
| [Windows NirSoft AdvancedRun](/endpoint/windows_nirsoft_advancedrun/) | None| TTP |
| [Windows NirSoft Utilities](/endpoint/windows_nirsoft_utilities/) | None| Hunting |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/windows_raw_access_to_master_boot_record_drive/) | None| TTP |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/wscript_or_cscript_suspicious_child_process/) | None| TTP |

#### Reference

* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
* [https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3](https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/whispergate.yml) \| *version*: **1**