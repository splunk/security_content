---
title: "Illegal Management of Active Directory Elements and Policies via DSInternals modules"
excerpt: "Account Manipulation, Rogue Domain Controller, Domain Policy Modification"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
tags:
  - TTP
  - T1098
  - Account Manipulation
  - Persistence
  - T1207
  - Rogue Domain Controller
  - Defense Evasion
  - T1484
  - Domain Policy Modification
  - Defense Evasion
  - Privilege Escalation
  - Splunk Behavioral Analytics
  - Actions on Objectives
---



#### Description

This detection identifies use of DSInternals modules for illegal management of Active Directoty elements and policies.

- **ID**: a587ca9f-c138-47b4-ba51-699f319b8cc5
- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-09
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence || [T1207](https://attack.mitre.org/techniques/T1207/) | Rogue Domain Controller | Defense Evasion || [T1484](https://attack.mitre.org/techniques/T1484/) | Domain Policy Modification | Defense Evasion, Privilege Escalation |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Remove-ADDBObject/)=true OR match_regex(cmd_line, /(?i)Set-ADDBDomainController/)=true OR match_regex(cmd_line, /(?i)Set-ADDBPrimaryGroup/)=true OR match_regex(cmd_line, /(?i)Set-LsaPolicyInformation/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
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

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 90.0 | 90 | 100 |



#### Reference

* [https://github.com/MichaelGrafnetter/DSInternals](https://github.com/MichaelGrafnetter/DSInternals)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484/logAllDSInternalsModules.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484/logAllDSInternalsModules.log)


[_source_](https://github.com/splunk/security_content/tree/develop/detections/endpoint/illegal_management_of_active_directory_elements_and_policies_via_dsinternals_modules.yml) | _version_: **1**