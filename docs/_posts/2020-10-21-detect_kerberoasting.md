---
title: "Detect Kerberoasting"
excerpt: "Kerberoasting"
categories:
  - Endpoint
last_modified_at: 2020-10-21
toc: true
tags:
  - TTP
  - T1558.003
  - Kerberoasting
  - Credential Access
  - Splunk Behavioral Analytics
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects a potential kerberoasting attack via service principal name requests

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-21
- **Author**: Xiao Lin, Splunk
- **ID**: dabdd6d7-3e10-42be-8711-4e124f7a3850


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |


#### Search

```
 
| from read_ssa_enriched_events() 
| eval _time=map_get(input_event, "_time"), EventCode=map_get(input_event, "event_code"), TicketOptions=map_get(input_event, "ticket_options"), TicketEncryptionType=map_get(input_event, "ticket_encryption_type"), ServiceName=map_get(input_event, "service_name"), ServiceID=map_get(input_event, "service_id"), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where EventCode="4769" AND TicketOptions="0x40810000" AND TicketEncryptionType="0x17" 
| first_time_event input_columns=["EventCode","TicketOptions","TicketEncryptionType","ServiceName","ServiceID"] 
| where first_time_EventCode_TicketOptions_TicketEncryptionType_ServiceName_ServiceID 
| eval start_time=_time, end_time=_time, body=create_map(["event_id", event_id, "EventCode", EventCode, "ServiceName", ServiceName, "TicketOptions", TicketOptions, "TicketEncryptionType", TicketEncryptionType]), entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null))
| select start_time, end_time, entities, body 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
The test data is converted from Windows Security Event logs generated from Attach Range simulation and used in SPL search and extended to SPL2

#### Required field
* service_name
* _time
* event_code
* ticket_encryption_type
* service_id
* ticket_options


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Older systems that support kerberos RC4 by default NetApp may generate false positives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 14.0 | 70 | 20 | Kerberoasting malware is potentially applying stolen credentials. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |



#### Reference

* [Initial ESCU implementation by Jose Hernandez and Patrick Bareiss](Initial ESCU implementation by Jose Hernandez and Patrick Bareiss)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_kerberoasting.yml) \| *version*: **2**