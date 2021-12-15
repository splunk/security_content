---
title: "Attempted Credential Dump From Registry via Reg exe"
excerpt: "OS Credential Dumping, Security Account Manager"
categories:
  - Endpoint
last_modified_at: 2021-11-29
toc: true
toc_label: ""
tags:
  - OS Credential Dumping
  - Credential Access
  - Security Account Manager
  - Credential Access
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of `reg.exe` attempting to export Windows registry keys that contain hashed credentials. Adversaries will utilize this technique to capture and perform offline password cracking.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-29
- **Author**: Jose Hernandez, Splunk
- **ID**: 14038953-e5f2-4daf-acff-5452062baf03


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |

#### Search

```
 
| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where process_name="cmd.exe" OR process_name="reg.exe" 
| where cmd_line != null  AND match_regex(cmd_line, /(?i)save\s+/)=true AND ( match_regex(cmd_line, /(?i)HKLM\\Security/)=true OR match_regex(cmd_line, /(?i)HKLM\\SAM/)=true OR match_regex(cmd_line, /(?i)HKLM\\System/)=true OR match_regex(cmd_line, /(?i)HKEY_LOCAL_MACHINE\\Security/)=true OR match_regex(cmd_line, /(?i)HKEY_LOCAL_MACHINE\\SAM/)=true OR match_regex(cmd_line, /(?i)HKEY_LOCAL_MACHINE\\System/)=true ) 
| eval start_time = timestamp, end_time = timestamp, entities = mvappend(dest_device_id, dest_user_id), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name]) 
| into write_ssa_detected_events(); 
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* process_name
* _time
* dest_device_id
* dest_user_id
* process
* cmd_line


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | An attempt to save registry keys storing credentials has been performed on $dest_device_id$ by $dest_user_id$ via process $process_name$. |




#### Reference

* [https://github.com/splunk/security_content/blob/55a17c65f9f56c2220000b62701765422b46125d/detections/attempted_credential_dump_from_registry_via_reg_exe.yml](https://github.com/splunk/security_content/blob/55a17c65f9f56c2220000b62701765422b46125d/detections/attempted_credential_dump_from_registry_via_reg_exe.yml)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml) \| *version*: **2**