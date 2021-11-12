---
title: "Unusually Long Command Line"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2020-10-06
toc: true
toc_label: ""
tags:
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Command lines that are extremely long may be indicative of malicious activity on your hosts. This search leverages the Splunk Streaming ML DSP plugin to help identify command lines with lengths that are unusual for a given user. This detection is inspired on Unusually Long Command Line authored by Rico Valdez.

- **Type**: Anomaly
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-06
- **Author**: Ignacio Bermudez Corrales, Splunk
- **ID**: 58f43aba-1775-445e-b19c-be2b87d83ae3

#### Search

```
 
| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval cmd_line=ucast(map_get(input_event, "process"), "string", null), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line!=null and dest_user_id!=null 
| eval cmd_line_norm=replace(cast(cmd_line, "string"), /\s(--?\w+)
|(\/\w+)/, " ARG"), cmd_line_norm=replace(cmd_line_norm, /\w:\\[^\s]+/, "PATH"), cmd_line_norm=replace(cmd_line_norm, /\d+/, "N"), input=parse_double(len(coalesce(cmd_line_norm, ""))) 
| select timestamp, process_name, dest_device_id, dest_user_id, cmd_line, input 
| adaptive_threshold algorithm="quantile" entity="process_name" window=60480000 
| where label AND quantile>0.99 
| first_time_event input_columns=["dest_device_id", "cmd_line"] 
| where first_time_dest_device_id_cmd_line 
| eval start_time = timestamp, end_time = timestamp, entities = mvappend(dest_device_id, dest_user_id), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Unusual Processes](/stories/unusual_processes)


#### How To Implement
You must be ingesting sysmon endpoint data that monitors command lines.

#### Required field
* process_name
* _time
* dest_device_id
* dest_user_id
* process


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
This detection may flag suspiciously long command lines when there is not sufficient evidence (samples) for a given process that this detection is tracking; or when there is high variability in the length of the command line for the tracked process. Also, some legitimate applications may use long command lines. Such is the case of Ansible, that encodes Powershell scripts using long base64. Attackers may use this technique to obfuscate their payloads.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 12.0 | 30 | 40 | A  process $process_name$ with a long commandline $cmd_line$ executed in host $dest_device_id$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/unusually_long_command_line.yml) \| *version*: **1**