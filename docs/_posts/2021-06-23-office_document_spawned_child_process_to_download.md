---
title: "Office Document Spawned Child Process To Download"
excerpt: "Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-06-23
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search is to detect potential malicious office document executing lolbin child process to download payload or other malware. Since most of the attacker abused the capability of office document to execute living on land application to blend it to the normal noise in the infected machine to cover its track.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 6fed27d2-9ec7-11eb-8fe4-aa665a019aa3


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```
`sysmon` EventCode=1 parent_process_name IN ("powerpnt.exe", "winword.exe", "excel.exe", "visio.exe") process_name = "*.exe" cmdline IN ("*http:*","*https:*")  NOT(OriginalFileName IN("firefox.exe", "chrome.exe","iexplore.exe","msedge.exe")) 
| stats min(_time) as firstTime max(_time) as lastTime count by parent_process_name process_name parent_process cmdline process_id OriginalFileName ProcessGuid Computer EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `office_document_spawned_child_process_to_download_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances office application and browser may be used.

#### Required field
* _time
* parent_process_name
* process_name
* parent_process
* cmdline
* process_id
* OriginalFileName
* ProcessGuid
* Computer
* EventCode


#### Kill Chain Phase
* Exploitation


#### Known False Positives
default browser not in the filter list



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Office document spawning suspicious child process on $dest$ |



#### Reference

* [https://app.any.run/tasks/92d7ef61-bfd7-4c92-bc15-322172b4ebec/#](https://app.any.run/tasks/92d7ef61-bfd7-4c92-bc15-322172b4ebec/#)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets2/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets2/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_document_spawned_child_process_to_download.yml) \| *version*: **2**