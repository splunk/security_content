---
title: "Credential Extraction native Microsoft debuggers via z command line option"
excerpt: "OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2020-10-18
toc: true
toc_label: ""
tags:
  - OS Credential Dumping
  - Credential Access
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Credential extraction is often an illegal recovery of credential material from secured authentication resources and repositories. This process may also involve decryption or other transformations of the stored credential material. Native Microsoft debuggers, such as kd, ntkd, livekd and windbg, can be leveraged to read credential material directly from memory and process dumps.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-18
- **Author**: Stanislav Miskovic, Splunk
- **ID**: adc51a77-90c9-4358-b43c-f10dd1a27d05


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
 
| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND process_name != null AND ( match_regex(process_name, /^(?i)ntkd\.exe/)=true OR match_regex(process_name, /^(?i)kd\.exe/)=true ) AND match_regex(cmd_line, /(?i)\-z\s+/)=true

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [Unusual Processes](/stories/unusual_processes)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* process_name
* _time
* dest_device_id
* dest_user_id
* process


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, using debuggers this way may be indicative of developers analyzing crash dumps of their code. Note, even for developers this is an unusual way of working on code - debuggers are mostly used to step through code, not analyze its crash dumps.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Malicious actor is extracting/decoding encoded credentials via Microsoft&#39;s native debugging tools. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logLiveKDFullKernelDump.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logLiveKDFullKernelDump.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/credential_extraction_native_microsoft_debuggers_via_z_command_line_option.yml) \| *version*: **1**