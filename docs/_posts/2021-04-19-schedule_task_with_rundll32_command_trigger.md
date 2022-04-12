---
title: "Schedule Task with Rundll32 Command Trigger"
excerpt: "Scheduled Task/Job
"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following query utilizes Windows Security EventCode 4698, `A scheduled task was created`, to identify suspicious tasks registered on Windows either via schtasks.exe OR TaskService with a command to be executed with a Rundll32. This technique is common in new trickbot that uses rundll32 to load is trickbot downloader. The search will return the first time and last time the task was registered, as well as the `Command` to be executed, `Task Name`, `Author`, `Enabled`, and whether it is `Hidden` or not. schtasks.exe is natively found in `C:\Windows\system32` and `C:\Windows\syswow64`. The following DLL(s) are loaded when schtasks.exe or TaskService is launched -`taskschd.dll`. If found loaded by another process, it is possible a scheduled task is being registered within that process context in memory. Upon triage, identify the task scheduled source. Was it schtasks.exe or via TaskService? Review the job created and the Command to be executed. Capture any artifacts on disk and review. Identify any parallel processes within the same timeframe to identify source.'

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: 75b00fd8-a0ff-11eb-8b31-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

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
`wineventlog_security` EventCode=4698 
| xmlkv Message 
| search Command IN ("*rundll32*") 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Task_Name, Command, Author, Enabled, Hidden, Arguments 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schedule_task_with_rundll32_command_trigger_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **schedule_task_with_rundll32_command_trigger_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* Task_Name
* Command
* Author
* Enabled
* Hidden
* Arguments


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the task schedule (Exa. Security Log EventCode 4698) endpoints. Tune and filter known instances of Task schedule used in your environment.

#### Known False Positives
unknown

#### Associated Analytic story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Trickbot](/stories/trickbot)
* [IcedID](/stories/icedid)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | A schedule task process commandline rundll32 arguments $Arguments$ in host $dest$ |


#### Reference

* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/tasksched/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/tasksched/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/schedule_task_with_rundll32_command_trigger.yml) \| *version*: **1**