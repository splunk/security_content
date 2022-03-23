---
title: "WBAdmin Delete System Backups"
excerpt: "Inhibit System Recovery"
categories:
  - Endpoint
last_modified_at: 2021-12-07
toc: true
toc_label: ""
tags:
  - Inhibit System Recovery
  - Impact
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for flags passed to wbadmin.exe (Windows Backup Administrator Tool) that delete backup files. This is typically used by ransomware to prevent recovery.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-12-07
- **Author**: Michael Haag, Splunk
- **ID**: 71efbf52-4dbb-4c00-a520-306aa546cbb7


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where (cmd_line IS NOT NULL AND process_name IS NOT NULL) AND (process_name="wbadmin.exe" AND like (cmd_line, "%delete%") OR like (cmd_line, "%catalog%") OR like (cmd_line, "%systemstatebackup%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `wbadmin_delete_system_backups_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint_Processess` datamodel.

#### Known False Positives
Administrators may modify the boot configuration.

#### Associated Analytic story
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ attempting to delete system backups. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md)
* [https://thedfirreport.com/2020/10/08/ryuks-return/](https://thedfirreport.com/2020/10/08/ryuks-return/)
* [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-security_bcdedit_wbadmin.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-security_bcdedit_wbadmin.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wbadmin_delete_system_backups.yml) \| *version*: **1**