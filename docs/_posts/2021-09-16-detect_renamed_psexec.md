---
title: "Detect Renamed PSExec"
excerpt: "System Services
, Service Execution
"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
toc_label: ""
tags:
  - System Services
  - Service Execution
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies renamed instances of `PsExec.exe` being utilized on an endpoint. Most instances, it is highly probable to capture `Psexec.exe` or other SysInternal utility usage with the command-line argument of `-accepteula`. During triage, validate this is the legitimate version of `PsExec` by reviewing the PE metadata. In addition, review parallel processes for further suspicious behavior.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Splunk
- **ID**: 683e6196-b8e8-11eb-9a79-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |

| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_psexec` by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_psexec_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_psexec](https://github.com/splunk/security_content/blob/develop/macros/process_psexec.yml)

Note that `detect_renamed_psexec_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Limited false positives should be present. It is possible some third party applications may use older versions of PsExec, filter as needed.

#### Associated Analytic story
* [SamSam Ransomware](/stories/samsam_ransomware)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [HAFNIUM Group](/stories/hafnium_group)
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | The following $process_name$ has been identified as renamed, spawning from $parent_process_name$ on $dest$ by $user$. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.yaml)
* [https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/](https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_renamed_psexec.yml) \| *version*: **3**