---
title: "Unload Sysmon Filter Driver"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2020-07-22
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

Attackers often disable security tools to avoid detection. This search looks for the usage of process `fltMC.exe` to unload a Sysmon Driver that will stop sysmon from collecting the data.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-07-22
- **Author**: Bhavin Patel, Splunk
- **ID**: e5928ff3-23eb-4d8b-b8a4-dcbc844fdfbe


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=fltMC.exe AND Processes.process=*unload* AND Processes.process=*SysmonDrv*  by Processes.process_name Processes.process_id Processes.parent_process_name Processes.process Processes.dest Processes.user 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
|`unload_sysmon_filter_driver_filter`
| table firstTime lastTime dest user count process_name process_id parent_process_name process
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `unload_sysmon_filter_driver_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model. This search is also shipped with `unload_sysmon_filter_driver_filter` macro, update this macro to filter out false positives.

#### Known False Positives


#### Associated Analytic story
* [Disabling Security Tools](/stories/disabling_security_tools)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 50 | 90 | Possible Sysmon filter driver unloading on $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/unload_sysmon_filter_driver.yml) \| *version*: **3**