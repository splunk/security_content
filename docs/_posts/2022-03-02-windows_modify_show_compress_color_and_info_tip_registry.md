---
title: "Windows Modify Show Compress Color And Info Tip Registry"
excerpt: "Modify Registry
"
categories:
  - Endpoint
last_modified_at: 2022-03-02
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

This analytic is to look for suspicious registry modification related to file compression color and information tips. This IOC was seen in hermetic wiper where it has a thread that will create this registry entry to change the color of compressed or encrypted files in NTFS file system as well as the pop up information tips. This is a good indicator that a process tries to modified one of the registry GlobalFolderOptions related to file compression attribution in terms of color in NTFS file system.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-03-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: b7548c2e-9a10-11ec-99e3-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path = "*\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced*" AND Registry.registry_value_name  IN("ShowCompColor", "ShowInfoTip") by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data 
| `windows_modify_show_compress_color_and_info_tip_registry_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_modify_show_compress_color_and_info_tip_registry_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_name
* Registry.dest Registry.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Registry` node.

#### Known False Positives
unknown

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Hermetic Wiper](/stories/hermetic_wiper)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | Registry modification in "ShowCompColor" and "ShowInfoTips" on $dest$ |




#### Reference

* [https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html](https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/globalfolderoptions_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/globalfolderoptions_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_modify_show_compress_color_and_info_tip_registry.yml) \| *version*: **1**