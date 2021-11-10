---
title: "Credential Extraction indicative of FGDump and CacheDump with s option"
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

Credential extraction is often an illegal recovery of credential material from secured authentication resources and repositories. This process may also involve decryption or other transformations of the stored credential material. FGdump is a newer version of pwdump tool that extracts NTLM and LanMan password hashes from Windows. Cachedump is a publicly-available tool that extracts cached password hashes from a system&#39;s registry.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-18
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 312582f2-5e91-42c1-a275-cd67f31373c8


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
 
| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND process_name != null AND parent_process_name != null AND match_regex(parent_process_name, /(?i)System32\\services.exe/)=true AND match_regex(process_name, /(?i)cachedump\d{0,2}.exe/)=true AND match_regex(process_path, /(?i)\\Temp/)=true AND match_regex(cmd_line, /(?i)\-s/)=true

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Unusual Processes](/stories/unusual_processes)
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* dest_device_id
* process_name
* parent_process_name
* _time
* process_path
* dest_user_id
* process


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | Malicious actor is accessing stored credentials via FGDump or CacheDump tools. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logFgdump.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logFgdump.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/credential_extraction_indicative_of_fgdump_and_cachedump_with_s_option.yml) \| *version*: **1**