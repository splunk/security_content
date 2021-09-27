---
title: "Credential Extraction via Get-ADDBAccount module present in PowerSploit and DSInternals"
excerpt: "OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2020-10-18
toc: true
tags:
  - TTP
  - T1003
  - OS Credential Dumping
  - Credential Access
  - Splunk Behavioral Analytics
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Credential extraction is often an illegal recovery of credential material from secured authentication resources and repositories. This process may also involve decryption or other transformations of the stored credential material. PowerSploit and DSInternals are common exploit APIs offering PowerShell modules for various exploits of Windows and Active Directory environments.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-18
- **Author**: Stanislav Miskovic, Splunk
- **ID**: e4f126b5-e6bc-4a5c-b1a8-d07bc6c4a49f


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |



#### Search

```
 
| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND match_regex(cmd_line, /(?i)Get-ADDBAccount/)=true AND match_regex(cmd_line, /(?i)\-dbpath[\s;:\.\
|]+/)=true

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [Malicious PowerShell](/stories/malicious_powershell)


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
| 63.0 | 70 | 90 | PowerSploit malware is accessing stored credentials via Get-ADDBAccount module. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logPowerShellModule.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logPowerShellModule.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/credential_extraction_via_get-addbaccount_module_present_in_powersploit_and_dsinternals.yml) \| *version*: **1**