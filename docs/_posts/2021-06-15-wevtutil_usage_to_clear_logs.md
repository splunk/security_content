---
title: "WevtUtil Usage To Clear Logs"
excerpt: "Clear Windows Event Logs"
categories:
  - Endpoint
last_modified_at: 2021-06-15
toc: true
tags:
  - TTP
  - T1070.001
  - Clear Windows Event Logs
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The wevtutil.exe application is the windows event log utility. This searches for wevtutil.exe with parameters for clearing the application, security, setup, powershell, sysmon, or system event logs.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-15
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5438113c-cdd9-11eb-93b8-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Defense Evasion |


#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND like(cmd_line, "% cl %") AND (match_regex(cmd_line, /(?i)security/)=true OR match_regex(cmd_line, /(?i)system/)=true OR match_regex(cmd_line, /(?i)sysmon/)=true OR match_regex(cmd_line, /(?i)application/)=true OR match_regex(cmd_line, /(?i)setup/)=true OR match_regex(cmd_line, /(?i)powershell/)=true) AND process_name="wevtutil.exe" 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Log Manipulation](/stories/windows_log_manipulation)
* [Ransomware](/stories/ransomware)
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process


#### Kill Chain Phase
* Exploitation


#### Known False Positives
The wevtutil.exe application is a legitimate Windows event log utility. Administrators may use it to manage Windows event logs.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A wevtutil process $process_name$ with commandline $cmd_line$ to clear event logs in host $dest_device_id$ |



#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-clop-ransomware.html](https://www.splunk.com/en_us/blog/security/detecting-clop-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/ssa_wevtutil/clear_evt.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/ssa_wevtutil/clear_evt.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wevtutil_usage_to_clear_logs.yml) \| *version*: **1**