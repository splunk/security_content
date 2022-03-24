---
title: "Windows Disable LogOff Button Through Registry"
excerpt: "Modify Registry
"
categories:
  - Endpoint
last_modified_at: 2022-03-08
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

This analytic is to detect a suspicious registry modification to disable logoff feature in windows host. This registry when enable will prevent users to log off of the system by using any method, including programs run from the command line, such as scripts. It also disables or removes all menu items and buttons that log the user off of the system. This technique was seen abused by ransomware malware to make the compromised host un-useful and hard to remove other registry modification made on the machine that needs restart to take effect. This windows feature may implement by administrator in some server where shutdown is critical. In that scenario filter of machine and users that can modify this registry is needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-03-08
- **Author**: Teoderick Contreras, Splunk
- **ID**: b2fb6830-9ed1-11ec-9fcb-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path= "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\*" Registry.registry_value_name IN ("NoLogOff", "StartMenuLogOff") Registry.registry_value_data = "0x00000001" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data 
| `windows_disable_logoff_button_through_registry_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_disable_logoff_button_through_registry_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_name
* Registry.dest Registry.user
* Processes.process_id
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_guid


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Registry` node.

#### Known False Positives
This windows feature may implement by administrator in some server where shutdown is critical. In that scenario filter of machine and users that can modify this registry is needed.

#### Associated Analytic story
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Registry modification in "NoLogOff" on $dest$ |




#### Reference

* [https://www.hybrid-analysis.com/sample/e2d4018fd3bd541c153af98ef7c25b2bf4a66bc3bfb89e437cde89fd08a9dd7b/5b1f4d947ca3e10f22714774](https://www.hybrid-analysis.com/sample/e2d4018fd3bd541c153af98ef7c25b2bf4a66bc3bfb89e437cde89fd08a9dd7b/5b1f4d947ca3e10f22714774)
* [https://malwiki.org/index.php?title=DigiPop.xp](https://malwiki.org/index.php?title=DigiPop.xp)
* [https://www.trendmicro.com/vinfo/be/threat-encyclopedia/search/js_noclose.e/2](https://www.trendmicro.com/vinfo/be/threat-encyclopedia/search/js_noclose.e/2)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_disable_logoff_button_through_registry.yml) \| *version*: **1**