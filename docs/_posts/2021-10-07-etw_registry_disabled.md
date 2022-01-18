---
title: "ETW Registry Disabled"
excerpt: "Indicator Blocking, Trusted Developer Utilities Proxy Execution, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-10-07
toc: true
toc_label: ""
tags:
  - Indicator Blocking
  - Defense Evasion
  - Trusted Developer Utilities Proxy Execution
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

This analytic is to detect a registry modification to disable ETW feature of windows. This technique is to evade EDR appliance to evade detections and hide its execution from audit logs.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: 8ed523ac-276b-11ec-ac39-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1562.006](https://attack.mitre.org/techniques/T1562/006/) | Indicator Blocking | Defense Evasion |

| [T1127](https://attack.mitre.org/techniques/T1127/) | Trusted Developer Utilities Proxy Execution | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where (Registry.registry_path="*\\SOFTWARE\\Microsoft\\.NETFramework*") Registry.registry_value_name = ETWEnabled Registry.registry_value_data=0x00000000 by Registry.dest Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `etw_registry_disabled_filter`
```

#### Associated Analytic Story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.registry_value_data


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | modified/added/deleted registry entry $Registry.registry_path$ in $dest$ |




#### Reference

* [https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3](https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/etw_disable/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/etw_disable/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/etw_registry_disabled.yml) \| *version*: **1**