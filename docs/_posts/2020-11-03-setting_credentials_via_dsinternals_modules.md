---
title: "Setting Credentials via DSInternals modules"
excerpt: "Exploitation for Privilege Escalation, Valid Accounts, Account Manipulation"
categories:
  - Endpoint
last_modified_at: 2020-11-03
toc: true
toc_label: ""
tags:
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Account Manipulation
  - Persistence
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies illegal setting of credentials via DSInternals modules.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-03
- **Author**: Stanislav Miskovic, Splunk
- **ID**: d5ef590f-9bde-49eb-9c63-2f5b62a65b9c


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), cmd_line=ucast(map_get(input_event, "process"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Add-ADDBSidHistory/)=true OR match_regex(cmd_line, /(?i)Add-ADReplNgcKey/)=true OR match_regex(cmd_line, /(?i)Set-ADDBAccountPassword/)=true OR match_regex(cmd_line, /(?i)Set-ADDBAccountPasswordHash/)=true OR match_regex(cmd_line, /(?i)Set-ADDBBootKey/)=true OR match_regex(cmd_line, /(?i)Set-SamAccountPasswordHash/)=true OR match_regex(cmd_line, /(?i)Set-AzureADUserEx/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


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
| 80.0 | 80 | 100 | DSInternals malware is accessing, using or setting Active Directory or Azure credentials and accounts. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/MichaelGrafnetter/DSInternals](https://github.com/MichaelGrafnetter/DSInternals)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/account_manipulation/logAllDSInternalsModules.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/account_manipulation/logAllDSInternalsModules.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/setting_credentials_via_dsinternals_modules.yml) \| *version*: **1**