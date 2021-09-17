---
title: "Reconnaissance and Access to Shared Resources via Mimikatz modules"
excerpt: "SMB/Windows Admin Shares, Network Share Discovery, Data from Network Shared Drive"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
tags:
  - TTP
  - T1021.002
  - SMB/Windows Admin Shares
  - Lateral Movement
  - T1135
  - Network Share Discovery
  - Discovery
  - T1039
  - Data from Network Shared Drive
  - Collection
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

#### Description

This detection identifies use of Mimikatz modules for discovery and access to network shares.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **Last Updated**: 2020-11-06
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement || [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | Discovery || [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Collection |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)net::share/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Discovery Techniques](_stories/windows_discovery_techniques)


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

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 70.0 | 70 | 100 |



#### Reference

* [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1