---
title: "Schedule Task with HTTP Command Arguments"
excerpt: "Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2021-04-19
toc: true
toc_label: ""
tags:
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following query utilizes Windows Security EventCode 4698, `A scheduled task was created`, to identify suspicious tasks registered on Windows either via schtasks.exe OR TaskService with an arguments &#34;HTTP&#34; string that are unique entry of malware or attack that uses lolbin to download other file or payload to the infected machine. The search will return the first time and last time the task was registered, as well as the `Command` to be executed, `Task Name`, `Author`, `Enabled`, and whether it is `Hidden` or not. schtasks.exe is natively found in `C:\Windows\system32` and `C:\Windows\syswow64`. The following DLL(s) are loaded when schtasks.exe or TaskService is launched -`taskschd.dll`. If found loaded by another process, it is possible a scheduled task is being registered within that process context in memory. Upon triage, identify the task scheduled source. Was it schtasks.exe or via TaskService? Review the job created and the Command to be executed. Capture any artifacts on disk and review. Identify any parallel processes within the same timeframe to identify source.&#39;

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: 523c2684-a101-11eb-916b-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```
`wineventlog_security` EventCode=4698 
| xmlkv Message
| search Arguments IN ("*http*") 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Task_Name, Command, Author, Enabled, Hidden, Arguments 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schedule_task_with_http_command_arguments_filter`
```

#### Associated Analytic Story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the task schedule (Exa. Security Log EventCode 4698) endpoints. Tune and filter known instances of Task schedule used in your environment.

#### Required field
* _time
* dest
* Task_Name
* Command
* Author
* Enabled
* Hidden
* Arguments


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A schedule task process commandline arguments $Arguments$ with http string on it in host $dest$ |




#### Reference

* [https://app.any.run/tasks/92d7ef61-bfd7-4c92-bc15-322172b4ebec/](https://app.any.run/tasks/92d7ef61-bfd7-4c92-bc15-322172b4ebec/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/tasksched/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/tasksched/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/schedule_task_with_http_command_arguments.yml) \| *version*: **1**