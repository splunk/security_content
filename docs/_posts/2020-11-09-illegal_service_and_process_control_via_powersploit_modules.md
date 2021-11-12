---
title: "Illegal Service and Process Control via PowerSploit modules"
excerpt: "Process Injection, Native API, System Services"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Native API
  - Execution
  - System Services
  - Execution
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules that enable illegal control of services and processes, such as installing or spoofing of malicious services, injecting malicious code in DLLs and EXEs, invoking shell code and WMI commands, modifying access to service objects, etc.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-09
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 0e910e5b-309d-4bc3-8af2-0030c02aa353


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

| [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | Execution |

| [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Install-SSP/)=true OR match_regex(cmd_line, /(?i)Set-CriticalProcess/)=true OR match_regex(cmd_line, /(?i)Install-ServiceBinary/)=true OR match_regex(cmd_line, /(?i)Restore-ServiceBinary/)=true OR match_regex(cmd_line, /(?i)Write-ServiceBinary/)=true OR match_regex(cmd_line, /(?i)Set-ServiceBinaryPath/)=true OR match_regex(cmd_line, /(?i)Invoke-ReflectivePEInjection/)=true OR match_regex(cmd_line, /(?i)Invoke-DllInjection/)=true OR match_regex(cmd_line, /(?i)Invoke-ServiceAbuse/)=true OR match_regex(cmd_line, /(?i)Invoke-Shellcode/)=true OR match_regex(cmd_line, /(?i)Invoke-WScriptUACBypass/)=true OR match_regex(cmd_line, /(?i)Invoke-WmiCommand/)=true OR match_regex(cmd_line, /(?i)Write-HijackDll/)=true OR match_regex(cmd_line, /(?i)Add-ServiceDacl/)=true )


| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Service Abuse](/stories/windows_service_abuse)
* [Malicious PowerShell](/stories/malicious_powershell)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* dest_device_id
* dest_user_id
* process
* _time


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | PowerSploit malware is controlling computer&#39;s processess and services. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllPowerSploitModulesWithOldNames.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllPowerSploitModulesWithOldNames.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/illegal_service_and_process_control_via_powersploit_modules.yml) \| *version*: **1**