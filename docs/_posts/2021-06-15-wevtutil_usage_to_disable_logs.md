---
title: "Wevtutil Usage To Disable Logs"
last_modified_at: 2021-06-15
categories:
  - Endpoint
tags:
  - Splunk Behavioral Analytics
  - T1070.001
  - Defense Evasion
---

This search is to detect execution of wevtutil.exe to disable logs. This technique was seen in several ransomware to disable the event logs to evade alerts and detections in compromised host.

#### Search

```

| from read_ssa_enriched_events()
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string
", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "eve
nt_id"), "string", null)
| where cmd_line IS NOT NULL AND like(cmd_line, "% sl %") AND like(cmd_line, "%/e:false%") AND process_name="wevtutil.exe"
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["ev
ent_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path])
| into write_ssa_detected_events();

```

#### Associated Analytic Story

* Windows Log Manipulation

* Ransomware


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from
 your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Required field

* _time

* dest_device_id

* process_name

* parent_process_name

* process_path

* dest_user_id

* process



#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
