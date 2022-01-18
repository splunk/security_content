---
title: "Disable Security Logs Using MiniNt Registry"
excerpt: "Modify Registry"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - Modify Registry
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious registry modification to disable security audit logs. This technique was shared by a researcher to disable Security logs of windows by adding this registry. The Windows will think it is WinPE and will not log any event to the Security Log

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: 39ebdc68-25b9-11ec-aec7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path="*\\Control\\MiniNt\\*" by Registry.dest Registry.user Registry.registry_value_name Registry.registry_key_name Registry.registry_path Registry.registry_value_data 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `disable_security_logs_using_minint_registry_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

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
Unknown.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | modified/added/deleted registry entry $Registry.registry_path$ in $dest$ |




#### Reference

* [https://twitter.com/0gtweet/status/1182516740955226112](https://twitter.com/0gtweet/status/1182516740955226112)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/minint_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/minint_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_security_logs_using_minint_registry.yml) \| *version*: **1**