---
title: "Attempt To Disable Services"
excerpt: "Service Stop"
categories:
  - Endpoint
last_modified_at: 2021-06-18
toc: true
tags:
  - TTP
  - T1489
  - Service Stop
  - Impact
  - Splunk Behavioral Analytics
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious series of command-line to disable several services. This technique is seen where the adversary attempts to disable security app services or other malware services to complete the objective on the compromised system.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-18
- **Author**: Teoderick Contreras, Splunk
- **ID**: afb31de4-d023-11eb-98d5-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop | Impact |



#### Search

```

| from read_ssa_enriched_events() 
| eval _datamodels=ucast(map_get(input_event, "_datamodels"), "collection<string>", []), body={} 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND like(cmd_line, "%disabled%") AND like(cmd_line, "%config%") AND process_name="sc.exe" 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed sc.exe may be used.

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
unknown




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/](https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/ssa_data1/sc_disable.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/ssa_data1/sc_disable.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/attempt_to_disable_services.yml) \| *version*: **1**