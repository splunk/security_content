---
title: "Change Default File Association"
excerpt: "Change Default File Association
, Event Triggered Execution
"
categories:
  - Endpoint
last_modified_at: 2021-09-27
toc: true
toc_label: ""
tags:
  - Change Default File Association
  - Event Triggered Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is developed to detect suspicious registry modification to change the default file association of windows to malicious payload. This techninique was seen in some APT where it modify the default process to run file association, like .txt to notepad.exe. Instead notepad.exe it will point to a Script or other payload that will load malicious command to the compromised host.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-09-27
- **Author**: Teoderick Contreras, Splunk
- **ID**: 462d17d8-1f71-11ec-ad07-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.001](https://attack.mitre.org/techniques/T1546/001/) | Change Default File Association | Persistence, Privilege Escalation |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path ="*\\shell\\open\\command\\*" Registry.registry_path = "*HKCR\\*" by Registry.dest  Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `change_default_file_association_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `change_default_file_association_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
unknown

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

* [https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/privilege-escalation/untitled-3/accessibility-features](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/privilege-escalation/untitled-3/accessibility-features)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.001/txtfile_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.001/txtfile_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/change_default_file_association.yml) \| *version*: **1**