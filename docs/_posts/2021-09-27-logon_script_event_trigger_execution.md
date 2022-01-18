---
title: "Logon Script Event Trigger Execution"
excerpt: "Boot or Logon Initialization Scripts, Logon Script (Windows)"
categories:
  - Endpoint
last_modified_at: 2021-09-27
toc: true
toc_label: ""
tags:
  - Boot or Logon Initialization Scripts
  - Persistence
  - Privilege Escalation
  - Logon Script (Windows)
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious modification of registry entry to persist and gain privilege escalation upon booting up of compromised host. This technique was seen in several APT and malware where it modify UserInitMprLogonScript registry entry to its malicious payload to be executed upon boot up of the machine.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-27
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4c38c264-1f74-11ec-b5fa-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1037](https://attack.mitre.org/techniques/T1037/) | Boot or Logon Initialization Scripts | Persistence, Privilege Escalation |

| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | Logon Script (Windows) | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path IN ("*\\Environment\\UserInitMprLogonScript") by Registry.dest  Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `logon_script_event_trigger_execution_filter`
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


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | modified/added/deleted registry entry $Registry.registry_path$ in $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1037/001](https://attack.mitre.org/techniques/T1037/001)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1037.001/logonscript_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1037.001/logonscript_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/logon_script_event_trigger_execution.yml) \| *version*: **1**