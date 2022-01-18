---
title: "Office Document Creating Schedule Task"
excerpt: "Phishing, Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-14
toc: true
toc_label: ""
tags:
  - Phishing
  - Initial Access
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search detects a potential malicious office document that create schedule task entry through macro VBA api or through loading taskschd.dll. This technique was seen in so many malicious macro malware that create persistence , beaconing using task schedule malware entry The search will return the first time and last time the task was registered, as well as the `Command` to be executed, `Task Name`, `Author`, `Enabled`, and whether it is `Hidden` or not. schtasks.exe is natively found in `C:\Windows\system32` and `C:\Windows\syswow64`. The following DLL(s) are loaded when schtasks.exe or TaskService is launched -`taskschd.dll`. If found loaded by another process, it&#39;s possible a scheduled task is being registered within that process context in memory. Upon triage, identify the task scheduled source. Was it schtasks.exe or via TaskService? Review the job created and the Command to be executed. Capture any artifacts on disk and review. Identify any parallel processes within the same timeframe to identify source.&#39;

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: cc8b7b74-9d0f-11eb-8342-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```
`sysmon` EventCode=7 process_name IN ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") ImageLoaded = "*\\taskschd.dll" 
| stats min(_time) as firstTime max(_time) as lastTime values(ImageLoaded) as AllImageLoaded count by Computer EventCode Image process_name ProcessId ProcessGuid 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `office_document_creating_schedule_task_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and ImageLoaded (Like sysmon EventCode 7) from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Also be sure to include those monitored dll to your own sysmon config.

#### Required field
* ImageLoaded
* AllImageLoaded
* Computer
* EventCode
* Image
* process_name
* ProcessId
* ProcessGuid
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Office document creating a schedule task on $dest$ |




#### Reference

* [https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/](https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/)
* [https://redcanary.com/threat-detection-report/techniques/scheduled-task-job/](https://redcanary.com/threat-detection-report/techniques/scheduled-task-job/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_document_creating_schedule_task.yml) \| *version*: **1**