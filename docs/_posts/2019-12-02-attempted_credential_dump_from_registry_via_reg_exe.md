---
title: "Attempted Credential Dump From Registry via Reg exe"
excerpt: "Security Account Manager"
categories:
  - Endpoint
last_modified_at: 2019-12-02
toc: true
tags:
  - TTP
  - T1003.002
  - Security Account Manager
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



#### Description

Monitor for execution of reg.exe with parameters specifying an export of keys that contain hashed credentials that attackers may try to crack offline.

- **ID**: e9fb4a59-c5fb-440a-9f24-191fbc6b2911
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-12-02
- **Author**: Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=reg.exe OR Processes.process_name=cmd.exe) Processes.process=*save* (Processes.process=*HKEY_LOCAL_MACHINE\\Security* OR Processes.process=*HKEY_LOCAL_MACHINE\\SAM* OR Processes.process=*HKEY_LOCAL_MACHINE\\System* OR Processes.process=*HKLM\\Security* OR Processes.process=*HKLM\\System* OR Processes.process=*HKLM\\SAM*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `attempted_credential_dump_from_registry_via_reg_exe_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [DarkSide Ransomware](/stories/darkside_ransomware)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints, to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 90.0 | 90 | 100 |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml) \| *version*: **4**