---
title: "Detect PsExec With accepteula Flag"
excerpt: "Remote Services
, SMB/Windows Admin Shares
"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
toc_label: ""
tags:
  - Remote Services
  - SMB/Windows Admin Shares
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for events where `PsExec.exe` is run with the `accepteula` flag in the command line. PsExec is a built-in Windows utility that enables you to execute processes on other systems. It is fully interactive for console applications. This tool is widely used for launching interactive command prompts on remote systems. Threat actors leverage this extensively for executing code on compromised systems. If an attacker is running PsExec for the first time, they will be prompted to accept the end-user license agreement (EULA), which can be passed as the argument `accepteula` within the command line.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-09-16
- **Author**: Bhavin Patel, Splunk
- **ID**: 27c3a83d-cada-47c6-9042-67baf19d2574


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_psexec` Processes.process=*accepteula* by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_psexec_with_accepteula_flag_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_psexec](https://github.com/splunk/security_content/blob/develop/macros/process_psexec.yml)

Note that `detect_psexec_with_accepteula_flag_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Administrators can leverage PsExec for accessing remote systems and might pass `accepteula` as an argument if they are running this tool for the first time. However, it is not likely that you'd see multiple occurrences of this event on a machine

#### Associated Analytic story
* [SamSam Ransomware](/stories/samsam_ransomware)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [HAFNIUM Group](/stories/hafnium_group)
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ running the utility for possibly the first time. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_psexec_with_accepteula_flag.yml) \| *version*: **4**