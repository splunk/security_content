---
title: "Excessive number of service control start as disabled"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-06-25
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

This detection targets behaviors observed when threat actors have used sc.exe to modify services. We observed malware in a honey pot spawning numerous sc.exe processes in a short period of time, presumably to impair defenses, possibly to block others from compromising the same machine.  This detection will alert when we see both an excessive number of sc.exe processes launched with specific commandline arguments to disable the start of certain services.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-25
- **Author**: Michael Hart, Splunk
- **ID**: 77592bec-d5cc-11eb-9e60-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` distinct_count(Processes.process) as distinct_cmdlines values(Processes.process_id) as process_ids min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process_name = "sc.exe" AND Processes.process="*start= disabled*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.parent_process_id, _time span=30m 
| where distinct_cmdlines >= 8 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_number_of_service_control_start_as_disabled_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must be ingesting logs with both the process name and command line from your endpoints. The complete process name with command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Legitimate programs and administrators will execute sc.exe with the start disabled flag.  It is possible, but unlikely from the telemetry of normal Windows operation we observed, that sc.exe will be called more than seven times in a short period of time.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An excessive amount of $process_name$ was executed on $dest$ attempting to disable services. |




#### Reference

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create)
* [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/sc_service_start_disabled/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/sc_service_start_disabled/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_number_of_service_control_start_as_disabled.yml) \| *version*: **1**