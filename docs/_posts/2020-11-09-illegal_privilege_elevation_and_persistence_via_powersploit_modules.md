---
title: "Illegal Privilege Elevation and Persistence via PowerSploit modules"
excerpt: "Scheduled Task/Job, Access Token Manipulation, Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
toc_label: ""
tags:
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Access Token Manipulation
  - Defense Evasion
  - Privilege Escalation
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules that illegaly elevate general privileges or ensure persistence, e.g., enable manipulation of registry, task scheduling, persistent WMI, access to OS objects under desired identities.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-09
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 88c10ee9-fe72-4bce-b343-5b129044b991


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

| [T1134](https://attack.mitre.org/techniques/T1134/) | Access Token Manipulation | Defense Evasion, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Add-DomainObjectAcl/)=true OR match_regex(cmd_line, /(?i)Add-ObjectAcl/)=true OR match_regex(cmd_line, /(?i)Enable-Privilege/)=true OR match_regex(cmd_line, /(?i)New-ElevatedPersistenceOption/)=true OR match_regex(cmd_line, /(?i)New-UserPersistenceOption/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


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
| 90.0 | 90 | 100 | PowerSploit malware is planting attack persistence elements, altering privileges and access controls. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/logAllPowerSploitModulesWithOldNames.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/logAllPowerSploitModulesWithOldNames.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/illegal_privilege_elevation_and_persistence_via_powersploit_modules.yml) \| *version*: **1**