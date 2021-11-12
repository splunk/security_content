---
title: "Credential Extraction indicative of use of DSInternals credential conversion modules"
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

Credential extraction is often an illegal recovery of credential material from secured authentication resources and repositories. This process may also involve decryption or other transformations of the stored credential material. DSInternals is a collection of PowerShell modules commonly employed in exploits.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-21
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 73e23834-c7ad-4860-bfd0-7d8ffe6527c2


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), cmd_line=ucast(map_get(input_event, "process"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)ConvertFrom-ADManagedPasswordBlob/)=true OR match_regex(cmd_line, /(?i)ConvertFrom-GPPrefPassword/)=true OR match_regex(cmd_line, /(?i)ConvertFrom-UnicodePassword/)=true OR match_regex(cmd_line, /(?i)ConvertTo-GPPrefPassword/)=true OR match_regex(cmd_line, /(?i)ConvertTo-KerberosKey/)=true OR match_regex(cmd_line, /(?i)ConvertTo-LMHash/)=true OR match_regex(cmd_line, /(?i)ConvertTo-NTHash/)=true OR match_regex(cmd_line, /(?i)ConvertTo-OrgIdHash/)=true OR match_regex(cmd_line, /(?i)ConvertTo-UnicodePassword/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [Malicious PowerShell](/stories/malicious_powershell)


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
| 70.0 | 70 | 100 | DSInternals tool kit is converting stolen credential material to a form applicable to authentications. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/MichaelGrafnetter/DSInternals](https://github.com/MichaelGrafnetter/DSInternals)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllDSInternalsModules.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllDSInternalsModules.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/credential_extraction_indicative_of_use_of_dsinternals_credential_conversion_modules.yml) \| *version*: **1**