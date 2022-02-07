---
title: "Disable Windows App Hotkeys"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2022-01-27
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

This analytic detects a suspicious registry modification to disable Windows hotkey (shortcut keys) for native Windows applications. This technique is commonly used to disable certain or several Windows applications like `taskmgr.exe` and `cmd.exe`. This technique is used to impair the analyst in analyzing and removing the attacker implant in compromised systems.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-27
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1490f224-ad8b-11eb-8c4f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry where Registry.registry_path="*\\Windows NT\\CurrentVersion\\Image File Execution Options\\*" AND Registry.registry_value_data= "HotKey Disabled" AND Registry.registry_value_name = "Debugger" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_key_name Registry.process_guid Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name 
| `disable_windows_app_hotkeys_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `disable_windows_app_hotkeys_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_name
* Registry.dest Registry.user


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as CarbonBlack or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Known False Positives
unknown

#### Associated Analytic story
* [XMRig](/stories/xmrig)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 40 | 100 | Disabled &#39;Windows App Hotkeys&#39; on $dest$ |




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/hotkey_disabled_hidden_user/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/hotkey_disabled_hidden_user/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_windows_app_hotkeys.yml) \| *version*: **2**