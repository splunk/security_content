---
title: "Disabling Defender Services"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-10-20
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

This particular behavior is typically executed when an adversaries or malware gains access to an endpoint and beings to perform execution and to evade detections. Usually, a batch (.bat) will be executed and multiple registry and scheduled task modifications will occur. During triage, review parallel processes and identify any further file modifications. Endpoint should be isolated.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: 911eacdc-317f-11ec-ad30-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path = "*\\System\\CurrentControlSet\\Services\\*" AND (Registry.registry_path IN("*WdBoot*", "*WdFilter*", "*WdNisDrv*", "*WdNisSvc*", "*WinDefend*", "*SecurityHealthService*"))  AND Registry.registry_value_name = Start Registry.registry_value_data = 0x00000004 by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `disabling_defender_services_filter`
```

#### Associated Analytic Story
* [IceID](/stories/iceid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

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
admin or user may choose to disable windows defender product


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | modified/added/deleted registry entry $registry_path$ in $dest$ |




#### Reference

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon2.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon2.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disabling_defender_services.yml) \| *version*: **1**