---
title: "Reconnaissance of Credential Stores and Services via Mimikatz modules"
excerpt: "Credentials, Domain Properties, Network Trust Dependencies, Exploitation for Privilege Escalation, Valid Accounts, Account Manipulation"
categories:
  - Endpoint
last_modified_at: 2020-11-03
toc: true
tags:
  - TTP
  - T1589.001
  - Credentials
  - Reconnaissance
  - T1590.001
  - Domain Properties
  - Reconnaissance
  - T1590.003
  - Network Trust Dependencies
  - Reconnaissance
  - T1068
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - T1078
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - T1098
  - Account Manipulation
  - Persistence
  - Splunk Behavioral Analytics
  - Actions on Objectives
---



#### Description

This detection identifies reconnaissance of credential stores and use of CryptoAPI services by Mimikatz modules.

- **ID**: 5facee5b-79e4-47ab-b0e6-c625acc0554f
- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-03
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1589.001](https://attack.mitre.org/techniques/T1589/001/) | Credentials | Reconnaissance || [T1590.001](https://attack.mitre.org/techniques/T1590/001/) | Domain Properties | Reconnaissance || [T1590.003](https://attack.mitre.org/techniques/T1590/003/) | Network Trust Dependencies | Reconnaissance || [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation || [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access || [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)crypto::capi/)=true OR match_regex(cmd_line, /(?i)crypto::cng/)=true OR match_regex(cmd_line, /(?i)crypto::providers/)=true OR match_regex(cmd_line, /(?i)crypto::stores/)=true OR match_regex(cmd_line, /(?i)crypto::sc/)=true )

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

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference

* [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[_source_](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_of_credential_stores_and_services_via_mimikatz_modules.yml) | _version_: **1**