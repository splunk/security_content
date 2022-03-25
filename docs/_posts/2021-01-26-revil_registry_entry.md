---
title: "Revil Registry Entry"
excerpt: "Modify Registry
"
categories:
  - Endpoint
last_modified_at: 2021-01-26
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies suspicious modification in registry entry to keep some malware data during its infection. This technique seen in several apt implant, malware and ransomware like REVIL where it keep some information like the random generated file extension it uses for all the encrypted files and ransomware notes file name in the compromised host.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-01-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: e3d3f57a-c381-11eb-9e35-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count  FROM datamodel=Endpoint.Registry where (Registry.registry_path="*\\SOFTWARE\\WOW6432Node\\Facebook_Assistant\\*" OR Registry.registry_path="*\\SOFTWARE\\WOW6432Node\\BlackLivesMatter*") by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data 
| `revil_registry_entry_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `revil_registry_entry_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_value_name
* Registry.registry_path
* Registry.registry_key_name


#### How To Implement
to successfully implement this search, you need to be ingesting logs with the Image, TargetObject registry key, registry Details from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [Ransomware](/stories/ransomware)
* [Revil Ransomware](/stories/revil_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 60.0 | 60 | 100 | A registry entry $registry_path$ with registry value $registry_value_name$ and $registry_value_name$ related to revil ransomware in host $dest$ |




#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/revil_registry_entry.yml) \| *version*: **2**