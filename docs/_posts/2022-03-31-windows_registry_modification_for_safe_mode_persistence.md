---
title: "Windows Registry Modification for Safe Mode Persistence"
excerpt: "Registry Run Keys / Startup Folder
, Boot or Logon Autostart Execution
"
categories:
  - Endpoint
last_modified_at: 2022-03-31
toc: true
toc_label: ""
tags:
  - Registry Run Keys / Startup Folder
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a modification or registry add to the safeboot registry as an autostart mechanism. This technique is utilized by adversaries to persist a driver or service into Safe Mode. Two keys are monitored in this analytic,  Minimal and Network. adding values to Minimal will load into Safe Mode and by adding into Network it will provide the service or drive the ability to perform network connections in Safe Mode.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-03-31
- **Author**: Teoderick Contreras, Michael Haag, Splunk
- **ID**: c6149154-c9d8-11eb-9da7-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path IN ("*SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\*","*SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\*") by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.process_guid Registry.registry_key_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
| join process_guid _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.process_guid 
| `drop_dm_object_name(Processes)`] 
| table _time dest user process_name process process_guid registry_path registry_value_name registry_value_data registry_key_name 
| `windows_registry_modification_for_safe_mode_persistence_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_registry_modification_for_safe_mode_persistence_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest
* Processes.process_id
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.process_guid


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Known False Positives
updated windows application needed in safe boot may used this registry

#### Associated Analytic story
* [Ransomware](/stories/ransomware)
* [Windows Registry Abuse](/stories/windows_registry_abuse)
* [Windows Drivers](/stories/windows_drivers)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | Safeboot registry $registry_path$ was added or modified with a new value $registry_value_name$ on $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://malware.news/t/threat-analysis-unit-tau-threat-intelligence-notification-snatch-ransomware/36365](https://malware.news/t/threat-analysis-unit-tau-threat-intelligence-notification-snatch-ransomware/36365)
* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md)
* [https://blog.didierstevens.com/2007/03/26/playing-with-safe-mode/](https://blog.didierstevens.com/2007/03/26/playing-with-safe-mode/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_registry_modification_for_safe_mode_persistence.yml) \| *version*: **3**