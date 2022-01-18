---
title: "Potential Pass the Token or Hash Observed by an Event Collecting Device"
excerpt: "Use Alternate Authentication Material, Pass the Hash"
categories:
  - Endpoint
last_modified_at: 2021-11-05
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
  - Authentication
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies potential Pass the Token or Pass the Hash credential stealing. We detect the main side effect of these attacks, which is a transition from the dominant Kerberos logins to rare NTLM logins for a given user, as reported by an event-collecting device (i.e., a specific domain controller or an endpoint destination).

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2021-11-05
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 1058ba3e-a698-49bc-a1e5-7cedece4ea87


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | Defense Evasion, Lateral Movement |

#### Search

```

| from read_ssa_enriched_events() 
| where "Authentication" IN(_datamodels)

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), dest_user=      lower(ucast(map_get(input_event, "dest_user_primary_artifact"), "string", null)), dest_user_id=   ucast(map_get(input_event, "dest_user_id"), "string", null), origin_device_id=       ucast(map_get(input_event, "origin_device_id"), "string", null), signature_id=   lower(ucast(map_get(input_event, "signature_id"), "string", null)), authentication_method=  lower(ucast(map_get(input_event, "authentication_method"), "string", null)), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where signature_id = "4624" AND (authentication_method="ntlmssp" OR authentication_method="kerberos") AND dest_user_id != null AND origin_device_id != null

| eval isKerberos=if(authentication_method == "kerberos", 1, 0), isNtlm=if(authentication_method == "ntlmssp", 1, 0), timeNTLM=if(isNtlm > 0, timestamp, null)

| stats sum(isKerberos) as totalKerberos, sum(isNtlm)     as totalNtlm, min(timestamp)  as startTime, min(timeNTLM)   as startNTLMTime, max(timestamp)  as endTime, max(timeNTLM)   as endNTLMTime by dest_user_id, dest_user, origin_device_id, span(timestamp, 86400s)

| where NOT dest_user="-" AND totalKerberos > 0 AND totalNtlm > 0 AND endTime - startTime > 1800000 AND (totalKerberos > 10 * totalNtlm AND totalKerberos > 50)  AND (endTime - startTime) > 3 * (endNTLMTime - startNTLMTime)

| eval start_time=startNTLMTime, end_time=endNTLMTime, entities=mvappend(dest_user_id, origin_device_id), body=create_map(["event_id", event_id, "total_kerberos", totalKerberos, "total_ntlm", totalNtlm, "analysis_start_time", startTime, "analysis_end_time", endTime, "detection_start_time", startNTLMTime, "detection_end_time", endNTLMTime])

| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest - at least from domain controllers. Please make sure that event ID 4624 is being logged.

#### Required field
* _time
* signature_id
* dest_user
* dest_user_id
* origin_device_id
* authentication_method


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Environments in which NTLM is used extremely rarely and for benign purposes (such as a rare use of SMB shares).


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | Potential lateral movement and credential stealing via Pass the Token or Pass the Hash techniques. Operation is performed via credentials of the account $dest_user_id$ and observed by the logging device $origin_device_id$ |




#### Reference

* [https://attack.mitre.org/techniques/T1550/002/](https://attack.mitre.org/techniques/T1550/002/)
* [https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/potential_pass_the_token_or_hash_observed_by_an_event_collecting_device.yml) \| *version*: **2**