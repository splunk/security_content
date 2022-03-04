---
title: "Windows Eventvwr UAC Bypass"
excerpt: "Bypass User Account Control, Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2022-02-18
toc: true
toc_label: ""
tags:
  - Bypass User Account Control
  - Privilege Escalation
  - Defense Evasion
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Registry
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following search identifies Eventvwr bypass by identifying the registry modification into a specific path that eventvwr.msc looks to (but is not valid) upon execution. A successful attack will include a suspicious command to be executed upon eventvwr.msc loading. Upon triage, review the parallel processes that have executed. Identify any additional registry modifications on the endpoint that may look suspicious. Remediate as necessary.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Registry](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointRegistry)
- **Last Updated**: 2022-02-18
- **Author**: Lou Stella, Splunk
- **ID**: 66adff66-90d9-11ec-aba7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Registry" IN (_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), registry_path=lower(ucast(map_get(input_event, "registry_path"), "string", null)), registry_hive=lower(ucast(map_get(input_event, "registry_hive"), "string", null)), registry_value_name=lower(ucast(map_get(input_event, "registry_value_name"), "string", null)), registry_key_name=lower(ucast(map_get(input_event, "parent_process_name"), "string", null)), registry_value_type=lower(ucast(map_get(input_event, "registry_value_type"), "string", null)), registry_value_data=lower(ucast(map_get(input_event, "registry_value_data"), "string", null)), process_guid=lower(ucast(map_get(input_event, "process_guid"), "string", null)) 
| where registry_path IS NOT NULL AND (like (registry_path, "%mscfile\\\\shell\\\\open\\\\command%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["registry_path", registry_path, "registry_hive", registry_hive, "registry_value_name", registry_value_name, "registry_key_name", registry_key_name, "registry_value_type", registry_value_type, "registry_value_data", registry_value_data, "process_guid", process_guid]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_eventvwr_uac_bypass_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* event_id
* registry_path
* registry_hive
* registry_value_name
* registry_key_name
* registry_value_type
* registry_value_data
* process_guid


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint_Registry` datamodel.

#### Known False Positives
None known at this time.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [IcedID](/stories/icedid)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Privilege Escalation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | Registry values were modified to bypass UAC using Event Viewer on $dest_device_id$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/](https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)
* [https://attack.mitre.org/techniques/T1548/002](https://attack.mitre.org/techniques/T1548/002)
* [https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/ssa_eventvwr/windows-sysmon-registry.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/ssa_eventvwr/windows-sysmon-registry.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_eventvwr_uac_bypass.yml) \| *version*: **1**