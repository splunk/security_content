---
title: "Detect Prohibited Applications Spawning cmd exe"
excerpt: "Command and Scripting Interpreter
, Windows Command Shell
"
categories:
  - Endpoint
last_modified_at: 2020-11-10
toc: true
toc_label: ""
tags:

  - Command and Scripting Interpreter
  - Windows Command Shell
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for executions of cmd.exe spawned by a process that is often abused by attackers and that does not typically launch cmd.exe.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-11-10
- **Author**: Bhavin Patel, Splunk
- **ID**: dcfd6b40-42f9-469d-a433-2e53f7486664


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval process_name=ucast(map_get(input_event, "process_name"), "string", null), parent_process=lower(ucast(map_get(input_event, "parent_process_name"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"),"string", null)), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), event_id=ucast(map_get(input_event,"event_id"), "string", null) 
| where process_name="cmd.exe" 
| rex field=parent_process "(?<ParentBaseFileName>[^\\\\]+)$" 
| where ParentBaseFileName="winword.exe" OR ParentBaseFileName="excel.exe" OR ParentBaseFileName="outlook.exe" OR ParentBaseFileName="powerpnt.exe" OR ParentBaseFileName="visio.exe" OR ParentBaseFileName="mspub.exe" OR ParentBaseFileName="acrobat.exe" OR ParentBaseFileName="acrord32.exe" OR ParentBaseFileName="iexplore.exe" OR ParentBaseFileName="opera.exe" OR ParentBaseFileName="firefox.exe" OR (ParentBaseFileName="java.exe" AND (cmd_line IS NULL OR (cmd_line IS NOT NULL AND match_regex(cmd_line, /(?i)patch1-Hotfix1a/)=false))) OR ParentBaseFileName="powershell.exe" OR (ParentBaseFileName="chrome.exe" AND (cmd_line IS NULL OR (cmd_line IS NOT NULL AND NOT like(cmd_line, "%chrome-extension%")))) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(dest_device_id, dest_user_id), body=create_map(["event_id", event_id,  "process_name", process_name, "parent_process_name", parent_process, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:
* [prohibited_apps_launching_cmd](https://github.com/splunk/security_content/blob/develop/macros/prohibited_apps_launching_cmd.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [process_cmd](https://github.com/splunk/security_content/blob/develop/macros/process_cmd.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_prohibited_applications_spawning_cmd_exe_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
You must be ingesting data that records process activity from your hosts and populates the Endpoint data model with the resultant dataset. This search includes a lookup file, `prohibited_apps_launching_cmd.csv`, that contains a list of processes that should not be spawning cmd.exe. You can modify this lookup to better suit your environment. To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
There are circumstances where an application may legitimately execute and interact with the Windows command-line interface. Investigate and modify the lookup file, as appropriate.

#### Associated Analytic story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)
* [Suspicious MSHTA Activity](/stories/suspicious_mshta_activity)
* [Suspicious Zoom Child Processes](/stories/suspicious_zoom_child_processes)
* [NOBELIUM Group](/stories/nobelium_group)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ running prohibited applications. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/powershell_spawn_cmd/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/powershell_spawn_cmd/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_prohibited_applications_spawning_cmd_exe.yml) \| *version*: **6**