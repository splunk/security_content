---
title: "Disable Windows SmartScreen Protection"
excerpt: "Disable or Modify Tools"
categories:
  - Endpoint
last_modified_at: 2021-03-31
toc: true
tags:
  - TTP
  - T1562.001
  - Disable or Modify Tools
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following search identifies a modification of registry to disable the smartscreen protection of windows machine. This is windows feature provide an early warning system against website that might engage in phishing attack or malware distribution. This modification are seen in RAT malware to cover their tracks upon downloading other of its component or other payload.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-31
- **Author**: Teoderick Contreras, Splunk
- **ID**: 664f0fd0-91ff-11eb-a56f-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path= "*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreenEnabled"  Registry.registry_value_name = "Off" by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `disable_windows_smartscreen_protection_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.user
* Registry.dest
* Registry.registry_value_nam


#### Kill Chain Phase
* Exploitation


#### Known False Positives
admin or user may choose to disable this windows features.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | The Windows Smartscreen was disabled on $dest$ by $user$. |



#### Reference

* [https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html](https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-system.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_windows_smartscreen_protection.yml) \| *version*: **1**