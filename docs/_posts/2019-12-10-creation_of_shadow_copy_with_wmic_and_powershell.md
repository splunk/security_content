---
title: "Creation of Shadow Copy with wmic and powershell"
excerpt: "NTDS"
categories:
  - Endpoint
last_modified_at: 2019-12-10
toc: true
tags:
  - TTP
  - T1003.003
  - NTDS
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

#### Description

This search detects the use of wmic and Powershell to create a shadow copy.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-12-10
- **Author**: Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | Credential Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wmic* OR Processes.process_name=powershell* Processes.process=*shadowcopy* Processes.process=*create* by Processes.user Processes.process_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `creation_of_shadow_copy_with_wmic_and_powershell_filter`
```

#### Associated Analytic Story
* [Credential Dumping](_stories/credential_dumping)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Legtimate administrator usage of wmic to create a shadow copy.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 81.0 | 90 | 90 |



#### Reference

* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log)


_version_: 1