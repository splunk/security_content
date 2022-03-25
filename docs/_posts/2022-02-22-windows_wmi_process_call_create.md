---
title: "Windows WMI Process Call Create"
excerpt: "Windows Management Instrumentation
"
categories:
  - Endpoint
last_modified_at: 2022-02-22
toc: true
toc_label: ""
tags:
  - Windows Management Instrumentation
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for wmi commandlines to execute or create process. This technique was used by adversaries or threat actor to execute their malicious payload in local or remote host. This hunting query is a good pivot to start to look further which process trigger the wmi or what process it execute locally or remotely.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-22
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0661c2de-93de-11ec-9833-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_wmic` Processes.process = "* process *" Processes.process = "* call *" Processes.process = "* create *" by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.original_file_name Processes.process_id Processes.parent_process_path Processes.process_guid Processes.parent_process_id Processes.dest Processes.user Processes.process_path 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_wmi_process_call_create_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_wmic](https://github.com/splunk/security_content/blob/develop/macros/process_wmic.yml)

Note that `windows_wmi_process_call_create_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
* Processes.process_guid


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Administrators may execute this command for testing or auditing.

#### Associated Analytic story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | process with $process$ commandline executed in $dest$ |




#### Reference

* [https://github.com/NVISOsecurity/sigma-public/blob/master/rules/windows/process_creation/win_susp_wmi_execution.yml](https://github.com/NVISOsecurity/sigma-public/blob/master/rules/windows/process_creation/win_susp_wmi_execution.yml)
* [https://github.com/redcanaryco/atomic-red-team/blob/2b804d25418004a5f1ba50e9dc637946ab8733c7/atomics/T1047/T1047.md](https://github.com/redcanaryco/atomic-red-team/blob/2b804d25418004a5f1ba50e9dc637946ab8733c7/atomics/T1047/T1047.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_wmi_process_call_create.yml) \| *version*: **1**