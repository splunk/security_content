---
title: "Anomalous Usage of Account Credentials"
excerpt: "Domain Accounts"
categories:
  - Endpoint
last_modified_at: 2021-12-07
toc: true
toc_label: ""
tags:
  - Domain Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This is an anomaly generating detection looking for multiple interactive logins within a specific time period. An insider threat may attempt to steal colleagues credentials in low tech, undetectable methods, in order to gain access to additional information or to hide their own behavior. This should capture their attempted use of those credentials on a workstation.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-12-07
- **Author**: Lou Stella, Splunk
- **ID**: 629cbf9e-5785-11ec-9611-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```

| from read_ssa_enriched_events() 
| eval device=ucast(map_get(input_event, "dest_device_id"), "string", null), auth_type=ucast(map_get(input_event, "authentication_type"), "string", null), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), src_user=ucast(map_get(input_event, "dest_user_original_artifact"), "string", null), signature_id=ucast(map_get(input_event, "EventCode"), "string", null) 
| where signature_id="4624" 
| where auth_type="2" OR auth_type="11" 
| where NOT (src_user="SYSTEM") AND NOT (src_user="ANONYMOUS LOGON") 
| stats estdc(src_user) AS user_counter by device, span(timestamp, 600s, 300s) 
| where user_counter>=2  
| rename window_end AS timestamp 
| eval start_time=window_start, end_time=timestamp, entities=mvappend(device), body=create_map(["user_counter", user_counter, "device", device]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `anomalous_usage_of_account_credentials_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this detection, you need to be ingesting logon events from workstations.

#### Known False Positives
Shared workstations can cause false positives

#### Associated Analytic story
* [Insider Threat](/stories/insider_threat)


#### Kill Chain Phase
* Privilege Escalation
* Lateral Movement



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 6.0 | 20 | 30 | Multiple interactive logins detected on $device$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_login/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_login/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/anomalous_usage_of_account_credentials.yml) \| *version*: **1**