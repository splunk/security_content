---
title: "Remote Process Instantiation via WMI and PowerShell"
excerpt: "Windows Management Instrumentation
"
categories:
  - Endpoint
last_modified_at: 2021-11-15
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

This analytic looks for the execution of `powershell.exe` leveraging the `Invoke-WmiMethod` commandlet complemented with arguments utilized to start a process on a remote endpoint by abusing WMI. Red Teams and adversaries alike may abuse WMI and `powershell.exe` for lateral movement and remote code execution.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-11-15
- **Author**: Mauricio Velazco, Splunk
- **ID**: 112638b4-4634-11ec-b9ab-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_powershell` (Processes.process="*Invoke-WmiMethod*" AND Processes.process="*-CN*" AND Processes.process="*-Class Win32_Process*" AND  Processes.process="*-Name create*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `remote_process_instantiation_via_wmi_and_powershell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_powershell](https://github.com/splunk/security_content/blob/develop/macros/process_powershell.yml)

Note that `remote_process_instantiation_via_wmi_and_powershell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints.

#### Known False Positives
Administrators may leverage WWMI and powershell.exe to start a process on remote systems, but this activity is usually limited to a small set of hosts or users.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 90 | 70 | A process was started on a remote endpoint from $dest by abusing WMI using PowerShell.exe |




#### Reference

* [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)
* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/remote_process_instantiation_via_wmi_and_powershell.yml) \| *version*: **1**