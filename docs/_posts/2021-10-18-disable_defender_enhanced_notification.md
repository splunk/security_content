---
title: "Disable Defender Enhanced Notification"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-10-18
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Defense Evasion
  - Impair Defenses
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious modification of registry to disable windows defender feature. This technique is to bypassed or evade detection from Windows Defender AV product specially the Enhanced Notification feature wher user or admin set to show or display alerts.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-18
- **Author**: Teoderick Contreras, Splunk
- **ID**: dc65678c-301f-11ec-8e30-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path = "*Microsoft\\Windows Defender\\Reporting*" Registry.registry_value_name = DisableEnhancedNotifications Registry.registry_value_data = 0x00000001 by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `disable_defender_enhanced_notification_filter`
```

#### Associated Analytic Story
* [IceID](/stories/iceid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the registry value name, registry path, and registry value data executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_value_name
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_data


#### Kill Chain Phase
* Exploitation


#### Known False Positives
user may choose to disable windows defender AV


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | modified/added/deleted registry entry $registry_path$ in $dest$ |




#### Reference

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_defender_enhanced_notification.yml) \| *version*: **1**