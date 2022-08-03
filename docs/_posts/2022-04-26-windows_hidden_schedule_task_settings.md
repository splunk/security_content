---
title: "Windows Hidden Schedule Task Settings"
excerpt: "Scheduled Task/Job
"
categories:
  - Endpoint
last_modified_at: 2022-04-26
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following query utilizes Windows Security EventCode 4698, A scheduled task was created, to identify suspicious tasks registered on Windows either via schtasks.exe OR TaskService with a hidden settings that are unique entry of malware like industroyer2 or attack that uses lolbin to download other file or payload to the infected machine.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0b730470-5fe8-4b13-93a7-fe0ad014d0cc


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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



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
| search Hidden = true 
| stats count min(_time) as firstTime max(_time) as lastTime by  Task_Name, Command, Author, Hidden, dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_hidden_schedule_task_settings_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_hidden_schedule_task_settings_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
* [Industroyer2](/stories/industroyer2)
* [Active Directory Discovery](/stories/active_directory_discovery)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A schedule task with hidden setting enable in host $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/)
* [https://cert.gov.ua/article/39518](https://cert.gov.ua/article/39518)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/hidden_schedule_task/security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/hidden_schedule_task/security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_hidden_schedule_task_settings.yml) \| *version*: **1**