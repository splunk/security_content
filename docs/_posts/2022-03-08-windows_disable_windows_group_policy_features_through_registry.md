---
title: "Windows Disable Windows Group Policy Features Through Registry"
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

This analytic is to detect a suspicious registry modification to disable windows features. These techniques are seen in several ransomware malware to impair the compromised host to make it hard for analyst to mitigate or response from the attack. Disabling these known features make the analysis and forensic response more hard. Disabling these feature is not so common but can still be implemented by the administrator for security purposes. In this scenario filters for users that are allowed doing this is needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-08
- **Author**: Teoderick Contreras, Splunk
- **ID**: 63a449ae-9f04-11ec-945e-acde48001122


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

* Exploitation


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

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path= "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\*" OR Registry.registry_path= "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\*" Registry.registry_value_name IN ("NoDesktop", "NoFind", "NoControlPanel", "NoFileMenu", "NoSetTaskbar", "NoTrayContextMenu", "TaskbarLockAll", "NoThemesTab","NoPropertiesMyDocuments","NoVisualStyleChoice","NoColorChoice","NoPropertiesMyDocuments") Registry.registry_value_data = "0x00000001" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data 
| `windows_disable_windows_group_policy_features_through_registry_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **windows_disable_windows_group_policy_features_through_registry_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
unknown

#### Associated Analytic story
* [Ransomware](/stories/ransomware)
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Windows Registry Abuse](/stories/windows_registry_abuse)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Registry modification to disable windows features on $dest$ |


#### Reference

* [https://hybrid-analysis.com/sample/ef1c427394c205580576d18ba68d5911089c7da0386f19d1ca126929d3e671ab?environmentId=120&lang=en](https://hybrid-analysis.com/sample/ef1c427394c205580576d18ba68d5911089c7da0386f19d1ca126929d3e671ab?environmentId=120&lang=en)
* [https://www.sophos.com/de-de/threat-center/threat-analyses/viruses-and-spyware/Troj~Krotten-N/detailed-analysis](https://www.sophos.com/de-de/threat-center/threat-analyses/viruses-and-spyware/Troj~Krotten-N/detailed-analysis)
* [https://www.virustotal.com/gui/file/2d7855bf6470aa323edf2949b54ce2a04d9e38770f1322c3d0420c2303178d91/details](https://www.virustotal.com/gui/file/2d7855bf6470aa323edf2949b54ce2a04d9e38770f1322c3d0420c2303178d91/details)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_disable_windows_group_policy_features_through_registry.yml) \| *version*: **1**