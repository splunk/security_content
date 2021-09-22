---
title: "Office Application Spawn rundll32 process"
excerpt: "Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-13
toc: true
tags:
  - TTP
  - T1566.001
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

this detection was designed to identifies suspicious spawned process of known MS office application due to macro or malicious code. this technique can be seen in so many malware like trickbot that used MS office as its weapon or attack vector to initially infect the machines.

- **ID**: 958751e4-9c5f-11eb-b103-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-13
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name = "winword.exe" OR Processes.parent_process_name = "excel.exe" OR Processes.parent_process_name = "powerpnt.exe") Processes.process_name=rundll32.exe  by Processes.parent_process Processes.process_name Processes.process_id Processes.process_guid Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `office_application_spawn_rundll32_process_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Trickbot](/stories/trickbot)
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* Processes.process
* Processes.parent_process_name
* _time
* Processes.process_name
* Processes.dest
* Processes.user
* Processes.process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference

* [https://any.run/malware-trends/trickbot](https://any.run/malware-trends/trickbot)
* [https://any.run/report/47561b4e949041eff0a0f4693c59c81726591779fe21183ae9185b5eb6a69847/aba3722a-b373-4dae-8273-8730fb40cdbe](https://any.run/report/47561b4e949041eff0a0f4693c59c81726591779fe21183ae9185b5eb6a69847/aba3722a-b373-4dae-8273-8730fb40cdbe)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_application_spawn_rundll32_process.yml) \| *version*: **1**