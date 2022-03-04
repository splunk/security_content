---
title: "Windows WSReset UAC Bypass"
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is built to detect a suspicious modification of the Windows registry related to UAC bypass. This technique is to modify the registry in this detection, create a registry value with the path of the payload and run WSreset.exe to bypass User Account Control.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Registry](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointRegistry)
- **Last Updated**: 2022-02-18
- **Author**: Lou Stella, Splunk
- **ID**: 3118f0c2-90d9-11ec-b833-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Registry" IN (_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), registry_path=lower(ucast(map_get(input_event, "registry_path"), "string", null)), registry_hive=lower(ucast(map_get(input_event, "registry_hive"), "string", null)), registry_value_name=lower(ucast(map_get(input_event, "registry_value_name"), "string", null)), registry_key_name=lower(ucast(map_get(input_event, "registry_key_name"), "string", null)), registry_value_type=lower(ucast(map_get(input_event, "registry_value_type"), "string", null)), registry_value_data=lower(ucast(map_get(input_event, "registry_value_data"), "string", null)), process_guid=lower(ucast(map_get(input_event, "process_guid"), "string", null)) 
| where registry_path IS NOT NULL AND registry_value_name IS NOT NULL and like (registry_path, "%\\\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\\\Shell\\\\open\\\\command%") AND (registry_value_name="(Default)" OR registry_value_name="DelegateExecute") 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["registry_path", registry_path, "registry_hive", registry_hive, "registry_value_name", registry_value_name, "registry_key_name", registry_key_name, "registry_value_type", registry_value_type, "registry_value_data", registry_value_data, "process_guid", process_guid]) 
| into write_ssa_detected_events(); 
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_wsreset_uac_bypass_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
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
Unknown at this point in time.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Privilege Escalation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | None |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)
* [https://blog.morphisec.com/trickbot-uses-a-new-windows-10-uac-bypass](https://blog.morphisec.com/trickbot-uses-a-new-windows-10-uac-bypass)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/windows_wsreset_uac_bypass.yml) \| *version*: **1**