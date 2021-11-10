---
title: "Reconnaissance and Access to Shared Resources via PowerSploit modules"
excerpt: "Remote Services, Data from Network Shared Drive, Network Share Discovery, SMB/Windows Admin Shares"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - Data from Network Shared Drive
  - Collection
  - Network Share Discovery
  - Discovery
  - SMB/Windows Admin Shares
  - Lateral Movement
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules that discover and access network and distributed file system shares.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 6b7ca431-6b1e-4b40-9589-21cb368e369e


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Collection |

| [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | Discovery |

| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Find-DomainShare/)=true OR match_regex(cmd_line, /(?i)Invoke-ShareFinder/)=true OR match_regex(cmd_line, /(?i)Find-InterestingDomainShareFile/)=true OR match_regex(cmd_line, /(?i)Invoke-FileFinder/)=true OR match_regex(cmd_line, /(?i)Find-InterestingFile/)=true OR match_regex(cmd_line, /(?i)Get-DomainDFSShare/)=true OR match_regex(cmd_line, /(?i)Get-DFSshare/)=true OR match_regex(cmd_line, /(?i)Get-NetShare/)=true )

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
| 70.0 | 70 | 100 | PowerSploit malware is searching for and accessing network shares. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_and_access_to_shared_resources_via_powersploit_modules.yml) \| *version*: **1**