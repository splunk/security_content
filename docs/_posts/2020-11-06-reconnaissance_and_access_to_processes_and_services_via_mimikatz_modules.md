---
title: "Reconnaissance and Access to Processes and Services via Mimikatz modules"
excerpt: "System Service Discovery, Network Service Scanning, Process Discovery"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
tags:
  - TTP
  - T1007
  - System Service Discovery
  - Discovery
  - T1046
  - Network Service Scanning
  - Discovery
  - T1057
  - Process Discovery
  - Discovery
  - Splunk Behavioral Analytics
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies use of Mimikatz modules for discovery and access to services and processes.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 0243d37c-57c1-4182-bfd1-39b212255fc8


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1007](https://attack.mitre.org/techniques/T1007/) | System Service Discovery | Discovery |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Scanning | Discovery |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Discovery |



#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)process::list/)=true OR match_regex(cmd_line, /(?i)service::list/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Discovery Techniques](/stories/windows_discovery_techniques)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* _time
* process
* dest_device_id
* dest_user_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 50.0 | 50 | 100 | Mimikatz malware is listing processes and services. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |



#### Reference

* [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_and_access_to_processes_and_services_via_mimikatz_modules.yml) \| *version*: **1**