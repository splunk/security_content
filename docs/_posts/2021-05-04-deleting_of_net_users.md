---
title: "Deleting Of Net Users"
excerpt: "Account Access Removal"
categories:
  - Endpoint
last_modified_at: 2021-05-04
toc: true
toc_label: ""
tags:
  - Account Access Removal
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect a suspicious net.exe/net1.exe command-line to delete a user on a system. This technique may be use by an administrator for legitimate purposes, however this behavior has been used in the wild to impair some user or deleting adversaries tracks created during its lateral movement additional systems. During triage, review parallel processes for additional behavior. Identify any other user accounts created before or after.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1c8c6f66-acce-11eb-aafb-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Impact |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_net` AND Processes.process="*user*" AND  Processes.process="*/delete*" by  Processes.process_name Processes.original_file_name Processes.dest Processes.user Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `deleting_of_net_users_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


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
* Exploitation


#### Known False Positives
System administrators or scripts may delete user accounts via this technique. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to delete accounts. |




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/deleting_of_net_users.yml) \| *version*: **2**