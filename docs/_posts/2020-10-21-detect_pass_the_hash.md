---
title: "Detect Pass the Hash"
excerpt: "Use Alternate Authentication Material, Pass the Hash"
categories:
  - Endpoint
last_modified_at: 2020-10-21
toc: true
toc_label: ""
tags:
  - Use Alternate Authentication Material
  - Defense Evasion
  - Lateral Movement
  - Pass the Hash
  - Defense Evasion
  - Lateral Movement
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for specific authentication events from the Windows Security Event logs to detect potential attempts using Pass-the-Hash technique.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-10-21
- **Author**: Xiao Lin, Splunk
- **ID**: 7cd8b9fa-6b0c-424f-92a6-9c5287a72f5f


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | Defense Evasion, Lateral Movement |

#### Search

```
 
| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval signature_id=map_get(input_event, "signature_id"), authentication_type=map_get(input_event, "authentication_type"), authentication_method=map_get(input_event, "authentication_method"), origin_device_domain=map_get(input_event, "origin_device_domain"), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null)

| where (authentication_type="3" AND authentication_method="NtLmSsp") OR (authentication_type="9" AND authentication_method="seclogo")

| eval start_time=timestamp, end_time=timestamp, entities=mvappend(dest_device_id, dest_user_id), body=create_map(["event_id", event_id, "authentication_type", authentication_type, "authentication_method", authentication_method]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Lateral Movement](/stories/lateral_movement)


#### How To Implement
The test data is converted from Windows Security Event logs generated from Attach Range simulation and used in SPL search and extended to SPL2

#### Required field
* signature_id
* authentication_type
* _time
* authentication_method
* origin_device_domain
* dest_user_id
* dest_device_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Legitimate logon activity by authorized NTLM systems may be detected by this search. Please investigate as appropriate.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 16.0 | 80 | 20 | Potential use of the pass the hash/token attacks that spoof authentication. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [Initial ESCU implementation by Bhavin Patel and Patrick Bareiss](Initial ESCU implementation by Bhavin Patel and Patrick Bareiss)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_pass_the_hash.yml) \| *version*: **1**