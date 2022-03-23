---
title: "Wevtutil Usage To Disable Logs"
excerpt: "Indicator Removal on Host, Clear Windows Event Logs"
categories:
  - Endpoint
last_modified_at: 2021-06-15
toc: true
toc_label: ""
tags:
  - Indicator Removal on Host
  - Defense Evasion
  - Clear Windows Event Logs
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect execution of wevtutil.exe to disable logs. This technique was seen in several ransomware to disable the event logs to evade alerts and detections in compromised host.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-06-15
- **Author**: Teoderick Contreras, Splunk
- **ID**: a4bdc944-cdd9-11eb-ac97-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND like(cmd_line, "% sl %") AND like(cmd_line, "%/e:false%") AND process_name="wevtutil.exe" 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `wevtutil_usage_to_disable_logs_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Known False Positives
network operator may disable audit event logs for debugging purposes.

#### Associated Analytic story
* [Windows Log Manipulation](/stories/windows_log_manipulation)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A wevtutil process $process_name$ with commandline $cmd_line$ to disable event logs in host $dest_device_id$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.bleepingcomputer.com/news/security/new-ransom-x-ransomware-used-in-texas-txdot-cyberattack/](https://www.bleepingcomputer.com/news/security/new-ransom-x-ransomware-used-in-texas-txdot-cyberattack/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/ssa_wevtutil/disable_evt.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/ssa_wevtutil/disable_evt.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wevtutil_usage_to_disable_logs.yml) \| *version*: **2**