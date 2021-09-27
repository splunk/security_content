---
title: "Delete A Net User"
excerpt: "Service Stop"
categories:
  - Endpoint
last_modified_at: 2021-06-21
toc: true
tags:
  - Anomaly
  - T1489
  - Service Stop
  - Impact
  - Splunk Behavioral Analytics
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect a suspicious net.exe/net1.exe command-line to delete a user on a system. This technique may be use by an administrator for legitimate purposes, however this behavior has been used in the wild to impair some user or deleting adversaries tracks created during its lateral movement additional systems. During triage, review parallel processes for additional behavior. Identify any other user accounts created before or after.

- **Type**: Anomaly
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 8776d79c-d26e-11eb-9a56-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop | Impact |



#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND like(cmd_line, "%/delete%") AND (process_name="net1.exe" OR process_name="net.exe") 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)
* [Ransomware](/stories/ransomware)


#### How To Implement
o successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed net.exe may be used.

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
System administrators or scripts may delete user accounts via this technique. Filter as needed.




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/ssa_data1/net_user_del.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/ssa_data1/net_user_del.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/delete_a_net_user.yml) \| *version*: **1**