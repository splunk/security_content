---
title: "Detect Prohibited Applications Spawning cmd exe"
excerpt: "Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2020-11-10
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies parent processes, browsers, Windows terminal applications, Office Products and Java spawning cmd.exe. By its very nature, many applications spawn cmd.exe natively or built into macros. Much of this will need to be tuned to further enhance the risk.

- **Type**: Anomaly
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2020-11-10
- **Author**: Ignacio Bermudez Corrales, Splunk
- **ID**: c10a18cb-fd80-4ffa-a844-25026e0a0c94


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval process_name=ucast(map_get(input_event, "process_name"), "string", null), parent_process=lower(ucast(map_get(input_event, "parent_process_name"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"),"string", null)), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), event_id=ucast(map_get(input_event,"event_id"), "string", null) 
| where process_name="cmd.exe" 
| rex field=parent_process "(?<ParentBaseFileName>[^\\\\]+)$" 
| where ParentBaseFileName="winword.exe" OR ParentBaseFileName="excel.exe" OR ParentBaseFileName="outlook.exe" OR ParentBaseFileName="powerpnt.exe" OR ParentBaseFileName="visio.exe" OR ParentBaseFileName="mspub.exe" OR ParentBaseFileName="acrobat.exe" OR ParentBaseFileName="acrord32.exe" OR ParentBaseFileName="iexplore.exe" OR ParentBaseFileName="opera.exe" OR ParentBaseFileName="firefox.exe" OR (ParentBaseFileName="java.exe" AND (cmd_line IS NULL OR (cmd_line IS NOT NULL AND NOT like(cmd_line, "%patch1-Hotfix1a%")))) OR ParentBaseFileName="powershell.exe" OR (ParentBaseFileName="chrome.exe" AND (cmd_line IS NULL OR (cmd_line IS NOT NULL AND NOT like(cmd_line, "%chrome-extension%")))) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(dest_device_id, dest_user_id), body=create_map(["event_id", event_id,  "process_name", process_name, "parent_process_name", parent_process, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)


#### How To Implement
In order to successfully implement this analytic, you will need endpoint process data from a EDR product or Sysmon. This search has been modified to process raw sysmon data from attack_range&#39;s nxlogs on DSP.

#### Required field
* process_name
* parent_process_name
* _time
* dest_device_id
* dest_user_id
* cmd_line


#### Kill Chain Phase
* Exploitation


#### Known False Positives
There are circumstances where an application may legitimately execute and interact with the Windows command-line interface.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$, producing a suspicious event that warrants investigating. |




#### Reference

* [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_prohibited_applications_spawning_cmd_exe.yml) \| *version*: **2**