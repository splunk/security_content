---
title: "Office Application Spawn rundll32 process"
excerpt: "Phishing
, Spearphishing Attachment
"
categories:
  - Endpoint
last_modified_at: 2021-04-13
toc: true
toc_label: ""
tags:
  - Phishing
  - Spearphishing Attachment
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

this detection was designed to identifies suspicious spawned process of known MS office application due to macro or malicious code. this technique can be seen in so many malware like trickbot that used MS office as its weapon or attack vector to initially infect the machines.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-04-13
- **Author**: Teoderick Contreras, Splunk
- **ID**: 958751e4-9c5f-11eb-b103-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name = "winword.exe" OR Processes.parent_process_name = "excel.exe" OR Processes.parent_process_name = "powerpnt.exe") AND `process_rundll32` by Processes.parent_process Processes.process_name Processes.process_id Processes.process_guid Processes.process Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `office_application_spawn_rundll32_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_rundll32](https://github.com/splunk/security_content/blob/develop/macros/process_rundll32.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `office_application_spawn_rundll32_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
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
unknown

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Trickbot](/stories/trickbot)
* [IcedID](/stories/icedid)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Office application spawning rundll32.exe on $dest$ |




#### Reference

* [https://any.run/malware-trends/trickbot](https://any.run/malware-trends/trickbot)
* [https://any.run/report/47561b4e949041eff0a0f4693c59c81726591779fe21183ae9185b5eb6a69847/aba3722a-b373-4dae-8273-8730fb40cdbe](https://any.run/report/47561b4e949041eff0a0f4693c59c81726591779fe21183ae9185b5eb6a69847/aba3722a-b373-4dae-8273-8730fb40cdbe)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_application_spawn_rundll32_process.yml) \| *version*: **2**