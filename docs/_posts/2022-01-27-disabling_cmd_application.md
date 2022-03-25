---
title: "Disabling CMD Application"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2022-01-27
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

this search is to identify modification in registry to disable cmd prompt application. This technique is commonly seen in RAT, Trojan or WORM to prevent triaging or deleting there samples through cmd application which is one of the tool of analyst to traverse on directory and files.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-01-27
- **Author**: Teoderick Contreras, Splunk
- **ID**: ff86077c-9212-11eb-a1e6-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path= "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\DisableCMD" Registry.registry_value_data = "0x00000001" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_key_name Registry.process_guid Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name 
| `disabling_cmd_application_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `disabling_cmd_application_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.user
* Registry.dest
* Registry.registry_value_name


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Known False Positives
admin may disable this application for non technical user.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | The Windows command prompt was disabled on $dest$ by $user$. |




#### Reference

* [https://any.run/report/ea4ea08407d4ee72e009103a3b77e5a09412b722fdef67315ea63f22011152af/a866d7b1-c236-4f26-a391-5ae32213dfc4#registry](https://any.run/report/ea4ea08407d4ee72e009103a3b77e5a09412b722fdef67315ea63f22011152af/a866d7b1-c236-4f26-a391-5ae32213dfc4#registry)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-system.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disabling_cmd_application.yml) \| *version*: **2**