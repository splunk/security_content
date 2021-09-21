---
title: "Create or delete windows shares using net exe"
excerpt: "Network Share Connection Removal"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
tags:
  - TTP
  - T1070.005
  - Network Share Connection Removal
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



#### Description

This search looks for the creation or deletion of hidden shares using net.exe.

- **ID**: qw9919ed-fe5f-492c-b139-151bb162140e
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1070.005](https://attack.mitre.org/techniques/T1070/005/) | Network Share Connection Removal | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count values(Processes.user) as user values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processs.process_name=net.exe OR Processes.process_name=net1.exe) by Processes.process Processes.process_name Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| search process=*share* 
| `create_or_delete_windows_shares_using_net_exe_filter` 
```

#### Associated Analytic Story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

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
Administrators often leverage net.exe to create or delete network shares. You should verify that the activity was intentional and is legitimate.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 25.0 | 50 | 50 |



#### Reference

* [https://attack.mitre.org/techniques/T1070/005](https://attack.mitre.org/techniques/T1070/005)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.005/atomic_red_team/windows-sysmon.log)


[_source_](https://github.com/splunk/security_content/tree/develop/detections/endpoint/create_or_delete_windows_shares_using_net_exe.yml) | _version_: **5**