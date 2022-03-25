---
title: "Clop Ransomware Known Service Name"
excerpt: "Create or Modify System Process
"
categories:
  - Endpoint
last_modified_at: 2021-03-17
toc: true
toc_label: ""
tags:
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection is to identify the common service name created by the CLOP ransomware as part of its persistence and high privilege code execution in the infected machine. Ussually CLOP ransomware use StartServiceCtrlDispatcherW API in creating this service entry.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-03-17
- **Author**: Teoderick Contreras
- **ID**: 07e08a12-870c-11eb-b5f9-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

#### Search

```
`wineventlog_system` EventCode=7045 Service_Name IN ("SecurityCenterIBM", "WinCheckDRVs") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `clop_ransomware_known_service_name_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)

Note that `clop_ransomware_known_service_name_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* EventCode
* cmdline
* _time
* parent_process_name
* process_name
* OriginalFileName
* process_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints.

#### Known False Positives
unknown

#### Associated Analytic story
* [Clop Ransomware](/stories/clop_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 100.0 | 100 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ executing known Clop Ransomware service names. |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/clop_ransomware_known_service_name.yml) \| *version*: **1**