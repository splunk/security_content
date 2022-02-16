---
title: "Modify ACLs Permission Of Files Or Folders"
excerpt: "File and Directory Permissions Modification"
categories:
  - Endpoint
last_modified_at: 2021-11-30
toc: true
toc_label: ""
tags:
  - File and Directory Permissions Modification
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies suspicious modification of ACL permission to a files or folder to make it available to everyone or to a specific user. This technique may be used by the adversary to evade ACLs or protected files access. This changes is commonly configured by the file or directory owner with appropriate permission. This behavior raises suspicion if this command is seen on an endpoint utilized by an account with no permission to do so.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-30
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9ae9a48a-cdbe-11eb-875a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND like(cmd_line, "%/G%") AND (match_regex(cmd_line, /(?i)everyone:/)=true OR match_regex(cmd_line, /(?i)SYSTEM:/)=true) AND (process_name="cacls.exe" OR process_name="xcacls.exe" OR process_name="icacls.exe") 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `modify_acls_permission_of_files_or_folders_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process
* cmd_line


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed cacls.exe may be used.

#### Known False Positives
System administrators may use this windows utility. filter is needed.

#### Associated Analytic story
* [XMRig](/stories/xmrig)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | A cacls process $process_name$ with commandline $cmd_line$ try to modify a permission of a file or directory in host $dest_device_id$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/ssa_cacls/all_icalc.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/ssa_cacls/all_icalc.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/modify_acls_permission_of_files_or_folders.yml) \| *version*: **2**