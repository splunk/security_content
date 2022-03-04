---
title: "WinEvent Scheduled Task Created Within Public Path"
excerpt: "Scheduled Task
, Scheduled Task/Job
"
categories:
  - Endpoint
last_modified_at: 2021-04-08
toc: true
toc_label: ""
tags:

  - Scheduled Task
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following query utilizes Windows Security EventCode 4698, `A scheduled task was created`, to identify suspicious tasks registered on Windows either via schtasks.exe OR TaskService with a command to be executed from a user writeable file path.\
The search will return the first time and last time the task was registered, as well as the `Command` to be executed, `Task Name`, `Author`, `Enabled`, and whether it is `Hidden` or not.\
schtasks.exe is natively found in `C:\Windows\system32` and `C:\Windows\syswow64`.\
The following DLL(s) are loaded when schtasks.exe or TaskService is launched -`taskschd.dll`. If found loaded by another process, it is possible a scheduled task is being registered within that process context in memory.\
Upon triage, identify the task scheduled source. Was it schtasks.exe or was it via TaskService. Review the job created and the Command to be executed. Capture any artifacts on disk and review. Identify any parallel processes within the same timeframe to identify source.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-04-08
- **Author**: Michael Haag, Splunk
- **ID**: 5d9c6eee-988c-11eb-8253-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```
`wineventlog_security` EventCode=4698 
| xmlkv Message 
| search Command IN ("*\\users\\public\\*", "*\\programdata\\*", "*\\temp\\*", "*\\Windows\\Tasks\\*", "*\\appdata\\*") 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Task_Name, Command, Author, Enabled, Hidden 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `winevent_scheduled_task_created_within_public_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `winevent_scheduled_task_created_within_public_path_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* Task_Name
* Description
* Command


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4698 EventCode enabled. The Windows TA is also required.

#### Known False Positives
False positives are possible if legitimate applications are allowed to register tasks in public paths. Filter as needed based on paths that are used legitimately.

#### Associated Analytic story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Ransomware](/stories/ransomware)
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [IcedID](/stories/icedid)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | A windows scheduled task was created (task name=$Task_Name$) on $dest$ by the following command: $Command$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/](https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/)
* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4698](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4698)
* [https://redcanary.com/threat-detection-report/techniques/scheduled-task-job/](https://redcanary.com/threat-detection-report/techniques/scheduled-task-job/)
* [https://docs.microsoft.com/en-us/windows/win32/taskschd/time-trigger-example--scripting-?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/windows/win32/taskschd/time-trigger-example--scripting-?redirectedfrom=MSDN)
* [https://app.any.run/tasks/e26f1b2e-befa-483b-91d2-e18636e2faf3/](https://app.any.run/tasks/e26f1b2e-befa-483b-91d2-e18636e2faf3/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/taskschedule/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/taskschedule/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/winevent_scheduled_task_created_within_public_path.yml) \| *version*: **1**