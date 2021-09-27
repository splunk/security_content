---
title: "Get WMIObject Group Discovery"
excerpt: "Local Groups"
categories:
  - Endpoint
last_modified_at: 2021-09-14
toc: true
tags:
  - Hunting
  - T1069.001
  - Local Groups
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic identifies the use of `Get-WMIObject Win32_Group` being used with PowerShell to identify local groups on the endpoint. \ Typically, by itself, is not malicious but may raise suspicion based on time of day, endpoint and username. \ During triage, review parallel processes and identify any further suspicious behavior.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-14
- **Author**: Michael Haag, Splunk
- **ID**: 5434f670-155d-11ec-8cca-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Local Groups | Discovery |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=powershell.exe OR processes.process_name=cmd.exe) (Processes.process="*Get-WMIObject*" AND Processes.process="*Win32_Group*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.original_file_name Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`  
| `get_wmiobject_group_discovery_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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
* Reconnaissance


#### Known False Positives
False positives may be present. Tune as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | System group discovery on $dest$ by $user$. |



#### Reference

* [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/get_wmiobject_group_discovery.yml) \| *version*: **1**