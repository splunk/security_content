---
title: "Windows Deleted Registry By A Non Critical Process File Path"
excerpt: "Modify Registry
"
categories:
  - Endpoint
last_modified_at: 2022-03-28
toc: true
toc_label: ""
tags:
  - Modify Registry
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect deletion of registry with suspicious process file path. This technique was seen in Double Zero wiper malware where it will delete all the subkey in HKLM, HKCU and HKU registry hive as part of its destructive payload to the targeted hosts. This anomaly detections can catch possible malware or advesaries deleting registry as part of defense evasion or even payload impact but can also catch for third party application updates or installation. In this scenario false positive filter is needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: 15e70689-f55b-489e-8a80-6d0cd6d8aad2


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">



</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.action=deleted by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_key_name Registry.process_guid Registry.registry_value_data Registry.action 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where NOT (Processes.process_path IN ("*\\windows\\*", "*\\program files*")) by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_path Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name action] 
| table _time parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name action dest user 
| `windows_deleted_registry_by_a_non_critical_process_file_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **windows_deleted_registry_by_a_non_critical_process_file_path_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_name
* Registry.dest
* Registry.user
* Registry.action
* Processes.process_id
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_guid
* Processes.process_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the registry value name, registry path, and registry value data from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
This detection can catch for third party application updates or installation. In this scenario false positive filter is needed.

#### Associated Analytic story
* [Double Zero Destructor](/stories/double_zero_destructor)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | registry was deleted by a suspicious $process_name$ with proces path $process_path in $dest$ |


#### Reference

* [https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html](https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/doublezero_wiper/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/doublezero_wiper/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_deleted_registry_by_a_non_critical_process_file_path.yml) \| *version*: **1**