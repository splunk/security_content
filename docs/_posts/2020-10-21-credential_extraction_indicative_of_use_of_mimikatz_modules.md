---
title: "Credential Extraction indicative of use of Mimikatz modules"
excerpt: "OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2020-10-21
toc: true
toc_label: ""
tags:
  - OS Credential Dumping
  - Credential Access
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Credential extraction is often an illegal recovery of credential material from secured authentication resources and repositories. This process may also involve decryption or other transformations of the stored credential material. Mimikatz is a collection of tools and modules commonly employed in Windows exploits.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-21
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 966b635f-98e8-4aa4-9b49-47ed2cedcc85


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)CRYPTO::Certificates/)=true OR match_regex(cmd_line, /(?i)CRYPTO::keys/)=true OR match_regex(cmd_line, /(?i)kerberos::list/)=true OR match_regex(cmd_line, /(?i)kerberos::tgt/)=true OR match_regex(cmd_line, /(?i)lsadump::sam/)=true OR match_regex(cmd_line, /(?i)lsadump::secrets/)=true OR match_regex(cmd_line, /(?i)lsadump::cache/)=true OR match_regex(cmd_line, /(?i)lsadump::lsa/)=true OR match_regex(cmd_line, /(?i)lsadump::trust/)=true OR match_regex(cmd_line, /(?i)lsadump::backupkeys/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [Unusual Processes](/stories/unusual_processes)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* dest_device_id
* dest_user_id
* process
* _time


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 66.5 | 70 | 95 | Mimikatz malware is extracting/decoding encoded credentials from stores such as SAM or LSA dumps. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllMimikatzModules.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllMimikatzModules.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/credential_extraction_indicative_of_use_of_mimikatz_modules.yml) \| *version*: **1**