---
title: "Modify ACL permission To Files Or Folder"
excerpt: "File and Directory Permissions Modification"
categories:
  - Endpoint
last_modified_at: 2021-05-04
toc: true
toc_label: ""
tags:
  - File and Directory Permissions Modification
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies suspicious modification of ACL permission to a files or folder to make it available to everyone. This technique may be used by the adversary to evade ACLs or protected files access. This changes is commonly configured by the file or directory owner with appropriate permission. This behavior is a good indicator if this command seen on a machine utilized by an account with no permission to do so.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7e8458cc-acca-11eb-9e3f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "cacls.exe" OR Processes.process_name = "icacls.exe" OR Processes.process_name = "xcacls.exe" AND (Processes.process = "*/G everyone:*"  OR Processes.process = "*/G SYSTEM:*") by Processes.parent_process_name Processes.process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `modify_acl_permission_to_files_or_folder_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed cacls.exe may be used.

#### Required field
* _time
* Processes.parent_process_name
* Processes.process_name
* Processes.dest
* Processes.user
* Processes.process
* Processes.process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
administrators may use this command. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 32.0 | 40 | 80 | Suspicious ACL permission modification on $dest$ |




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/modify_acl_permission_to_files_or_folder.yml) \| *version*: **1**