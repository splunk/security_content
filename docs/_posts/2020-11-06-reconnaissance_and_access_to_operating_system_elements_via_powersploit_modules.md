---
title: "Reconnaissance and Access to Operating System Elements via PowerSploit modules"
excerpt: "Process Discovery, File and Directory Discovery, Software, Network Service Scanning, Query Registry, System Service Discovery, Windows Management Instrumentation, Gather Victim Host Information, Software Discovery"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Process Discovery
  - Discovery
  - File and Directory Discovery
  - Discovery
  - Software
  - Reconnaissance
  - Network Service Scanning
  - Discovery
  - Query Registry
  - Discovery
  - System Service Discovery
  - Discovery
  - Windows Management Instrumentation
  - Execution
  - Gather Victim Host Information
  - Reconnaissance
  - Software Discovery
  - Discovery
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules that discover and access operating system elements, such as processes, services, registry locations, security packages and files.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Stanislav Miskovic, Splunk
- **ID**: c1d33ad9-1727-4f9f-a474-4adbe4fed68a


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Discovery |

| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Discovery |

| [T1592.002](https://attack.mitre.org/techniques/T1592/002/) | Software | Reconnaissance |

| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Scanning | Discovery |

| [T1012](https://attack.mitre.org/techniques/T1012/) | Query Registry | Discovery |

| [T1007](https://attack.mitre.org/techniques/T1007/) | System Service Discovery | Discovery |

| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

| [T1518](https://attack.mitre.org/techniques/T1518/) | Software Discovery | Discovery |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Find-DomainProcess/)=true OR match_regex(cmd_line, /(?i)Invoke-ProcessHunter/)=true OR match_regex(cmd_line, /(?i)Get-ServiceDetail/)=true OR match_regex(cmd_line, /(?i)Get-WMIProcess/)=true OR match_regex(cmd_line, /(?i)Get-NetProcess/)=true OR match_regex(cmd_line, /(?i)Get-SecurityPackage/)=true OR match_regex(cmd_line, /(?i)Find-DomainObjectPropertyOutlier/)=true OR match_regex(cmd_line, /(?i)Get-DomainObject/)=true OR match_regex(cmd_line, /(?i)Get-ADObject/)=true OR match_regex(cmd_line, /(?i)Get-WMIRegMountedDrive/)=true OR match_regex(cmd_line, /(?i)Get-RegistryMountedDrive/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Discovery Techniques](/stories/windows_discovery_techniques)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* _time
* process
* dest_device_id
* dest_user_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | PowerSploit malware is searching for and tapping into ongoing processes, mounted drives or other operating system elements. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_and_access_to_operating_system_elements_via_powersploit_modules.yml) \| *version*: **1**