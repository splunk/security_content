---
title: "Illegal Service and Process Control via Mimikatz modules"
excerpt: "Process Injection, Native API, System Services"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
tags:
  - TTP
  - T1055
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - T1106
  - Native API
  - Execution
  - T1569
  - System Services
  - Execution
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

#### Description

This detection identifies use of Mimikatz modules for illegal control over services and processes, including the authentication service.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **Last Updated**: 2020-11-09
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation || [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | Execution || [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)process::start/)=true OR match_regex(cmd_line, /(?i)service::\+/)=true OR match_regex(cmd_line, /(?i)service::\-/)=true OR match_regex(cmd_line, /(?i)service::start/)=true OR match_regex(cmd_line, /(?i)service::stop/)=true OR match_regex(cmd_line, /(?i)service::suspend/)=true OR match_regex(cmd_line, /(?i)misc::memssp/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Service Abuse](_stories/windows_service_abuse)


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

* [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllMimikatzModules.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllMimikatzModules.log)


_version_: 1