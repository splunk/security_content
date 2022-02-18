---
title: "Disable Defender AntiVirus Registry"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-12-08
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Defense Evasion
  - Impair Defenses
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Registry
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This particular behavior is typically executed when an adversaries or malware gains access to an endpoint and beings to perform execution and to evade detections. Usually, a batch (.bat) will be executed and multiple registry and scheduled task modifications will occur. During triage, review parallel processes and identify any further file modifications. Endpoint should be isolated.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Registry](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointRegistry)
- **Last Updated**: 2021-12-08
- **Author**: Bhavin Patel, Splunk
- **ID**: aa4f115a-3024-11ec-9987-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event,"_time"), "string", null)), registry_path=lower(ucast(map_get(input_event, "registry_path"), "string", null)), registry_key_name=lower(ucast(map_get(input_event, "registry_key_name"), "string", null)), registry_value_data=ucast(map_get(input_event, "registry_value_data"), "string", null), process_guid=ucast(map_get(input_event, "process_guid"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where like(registry_path, "%\\Policies\\Microsoft\\Windows Defender%") AND registry_key_name="DisableAntiVirus" AND registry_value_data="(0x00000001)" 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map( [ "event_id", event_id, "registry_path", registry_path, "registry_key_name", registry_key_name, "process_guid", process_guid,"registry_value_data",registry_value_data]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `disable_defender_antivirus_registry_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_value_name
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_data


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the registry value name, registry path, and registry value data from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Admin or user may choose to disable windows defender product

#### Associated Analytic story
* [IceID](/stories/iceid)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Modified/added/deleted registry entry $registry_path$ in $dest$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/disable_defender_antivirus_registry.yml) \| *version*: **1**