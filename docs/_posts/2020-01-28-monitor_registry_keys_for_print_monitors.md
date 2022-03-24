---
title: "Monitor Registry Keys for Print Monitors"
excerpt: "Port Monitors
, Boot or Logon Autostart Execution
"
categories:
  - Endpoint
last_modified_at: 2020-01-28
toc: true
toc_label: ""
tags:
  - Port Monitors
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for registry activity associated with modifications to the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`. In this scenario, an attacker can load an arbitrary .dll into the print-monitor registry by giving the full path name to the after.dll. The system will execute the .dll with elevated (SYSTEM) permissions and will persist after reboot.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-01-28
- **Author**: Bhavin Patel, Teoderick Contreras, Splunk
- **ID**: f5f6af30-7ba7-4295-bfe9-07de87c01bbc


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1547.010](https://attack.mitre.org/techniques/T1547/010/) | Port Monitors | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry where Registry.action=modified AND Registry.registry_path="*CurrentControlSet\\Control\\Print\\Monitors*" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.process_guid Registry.registry_key_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name 
| `monitor_registry_keys_for_print_monitors_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `monitor_registry_keys_for_print_monitors_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.action
* Registry.registry_path
* Registry.dest
* Registry.registry_key_name
* Registry.user
* Registry.registry_value_name


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or via other endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report registry modifications.

#### Known False Positives
You will encounter noise from legitimate print-monitor registry entries.

#### Associated Analytic story
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | New print monitor added on $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.010/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.010/atomic_red_team/windows-sysmon.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.010/atomic_red_team/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.010/atomic_red_team/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/monitor_registry_keys_for_print_monitors.yml) \| *version*: **3**