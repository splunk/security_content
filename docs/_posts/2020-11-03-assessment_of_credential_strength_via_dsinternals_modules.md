---
title: "Assessment of Credential Strength via DSInternals modules"
excerpt: "Valid Accounts, Account Manipulation, Account Discovery, Password Policy Discovery, Unsecured Credentials, Credentials from Password Stores"
categories:
  - Endpoint
last_modified_at: 2020-11-03
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Account Manipulation
  - Persistence
  - Account Discovery
  - Discovery
  - Password Policy Discovery
  - Discovery
  - Unsecured Credentials
  - Credential Access
  - Credentials from Password Stores
  - Credential Access
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies use of DSInternals modules that verify password strength, i.e., identify week accounts that would be easily compromised.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-03
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 5526d3a4-2497-4e8d-9d3c-7a34c9aace2f


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

| [T1201](https://attack.mitre.org/techniques/T1201/) | Password Policy Discovery | Discovery |

| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Credential Access |

| [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores | Credential Access |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Test-PasswordQuality/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* _time
* process
* dest_device_id
* dest_user_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.5 | 30 | 85 | DSInternals tool kit is assessing password strength at the device $dest_device_id$. Account attempting this operation is $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/MichaelGrafnetter/DSInternals](https://github.com/MichaelGrafnetter/DSInternals)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/assessment_of_credential_strength_via_dsinternals_modules.yml) \| *version*: **1**