---
title: "Time Provider Persistence Registry"
excerpt: "Time Providers, Boot or Logon Autostart Execution"
categories:
  - Endpoint
last_modified_at: 2021-09-29
toc: true
toc_label: ""
tags:
  - Time Providers
  - Persistence
  - Privilege Escalation
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspiciouos modification of time provider registry for persistence and autostart. This technique can allow the attacker to persist on the compromised host and autostart as soon as the machine boot up. This TTP can be a good indicator of suspicious behavior since this registry is not commonly modified by normal user or even an admin.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5ba382c4-2105-11ec-8d8f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1547.003](https://attack.mitre.org/techniques/T1547/003/) | Time Providers | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path ="*\\CurrentControlSet\\Services\\W32Time\\TimeProviders*" by Registry.dest  Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `time_provider_persistence_registry_filter`
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

* [https://pentestlab.blog/2019/10/22/persistence-time-providers/](https://pentestlab.blog/2019/10/22/persistence-time-providers/)
* [https://attack.mitre.org/techniques/T1547/003/](https://attack.mitre.org/techniques/T1547/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.003/timeprovider_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.003/timeprovider_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/time_provider_persistence_registry.yml) \| *version*: **1**