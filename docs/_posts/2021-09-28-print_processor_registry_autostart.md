---
title: "Print Processor Registry Autostart"
excerpt: "Print Processors
, Boot or Logon Autostart Execution
"
categories:
  - Endpoint
last_modified_at: 2021-09-28
toc: true
toc_label: ""
tags:
  - Print Processors
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious modification or new registry entry regarding print processor. This registry is known to be abuse by turla or other APT to gain persistence and privilege escalation to the compromised machine. This is done by adding the malicious dll payload on the new created key in this registry that will be executed as it restarted the spoolsv.exe process and services.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1f5b68aa-2037-11ec-898e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1547.012](https://attack.mitre.org/techniques/T1547/012/) | Print Processors | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path ="*\\Control\\Print\\Environments\\Windows x64\\Print Processors*" by Registry.dest  Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `print_processor_registry_autostart_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `print_processor_registry_autostart_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Known False Positives
possible new printer installation may add driver component on this registry.

#### Associated Analytic story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | modified/added/deleted registry entry $Registry.registry_path$ in $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1547/012/](https://attack.mitre.org/techniques/T1547/012/)
* [https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/print_reg/sysmon_print.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/print_reg/sysmon_print.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/print_processor_registry_autostart.yml) \| *version*: **1**