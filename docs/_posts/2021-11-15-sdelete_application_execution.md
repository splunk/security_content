---
title: "Sdelete Application Execution"
excerpt: "Data Destruction, File Deletion, Indicator Removal on Host"
categories:
  - Endpoint
last_modified_at: 2021-11-15
toc: true
toc_label: ""
tags:
  - Data Destruction
  - Impact
  - File Deletion
  - Defense Evasion
  - Indicator Removal on Host
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect the execution of sdelete.exe attempting to delete potentially important files that may related to adversary or insider threats to destroy evidence or information sabotage. Sdelete is a SysInternals utility meant to securely delete files on disk. This tool is commonly used to clear tracks and artifact on the targeted host.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-15
- **Author**: Teoderick Contreras, Splunk
- **ID**: fcc52b9a-4616-11ec-8454-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Defense Evasion |

| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event,"_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), parent_cmd_line=ucast(map_get(input_event, "parent_process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND like(process_name, "%sdelete%") AND (like (cmd_line, "%-c %") OR like (cmd_line, "%-f %")OR like (cmd_line, "%-p %") OR like (cmd_line, "%-r %") OR like (cmd_line, "%-q %") OR like (cmd_line, "%-s %") OR like (cmd_line, "%-z %") OR like (cmd_line, "%/accepteula%") OR like (cmd_line, "%-nobanner%")OR like (cmd_line, "%.doc%")OR like (cmd_line, "%.xls%") OR like (cmd_line, "%.ppt%")OR like (cmd_line, "%.rtf%") OR like (cmd_line, "%.pdf%") OR like (cmd_line, "%.key%")OR like (cmd_line, "%.log%") OR like (cmd_line, "%.txt%") OR like (cmd_line, "%.jpg%") OR like (cmd_line, "%.png%") OR like (cmd_line, "%.gif%") OR like (cmd_line, "%.bmp%") OR like (cmd_line, "%.7z%")  OR like (cmd_line, "%.zip%") OR like (cmd_line, "%.rar%") OR like (cmd_line, "%.tar%") OR like (cmd_line, "%.gz%") OR like (cmd_line, "%.xls%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "process_path", process_path, "parent_process_name", parent_process_name, "parent_cmd_line", parent_cmd_line]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `sdelete_application_execution_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* user
* parent_process_name
* parent_process
* process_name
* process
* process_id
* process_path
* cmd_line


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited, filter as needed.

#### Associated Analytic story
* [Information Sabotage](/stories/information_sabotage)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | Sdelete process $process_name$ executed on $dest_device_id$ attempting to permanently delete files by $dest_user_id$. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/sdelete/security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/sdelete/security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/sdelete_application_execution.yml) \| *version*: **1**