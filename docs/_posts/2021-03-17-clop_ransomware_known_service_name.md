---
title: "Clop Ransomware Known Service Name"
excerpt: "Create or Modify System Process"
categories:
  - Endpoint
last_modified_at: 2021-03-17
toc: true
tags:
  - TTP
  - T1543
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Privilege Escalation
---



#### Description

This detection is to identify the common service name created by the CLOP ransomware as part of its persistence and high privilege code execution in the infected machine. Ussually CLOP ransomware use StartServiceCtrlDispatcherW API in creating this service entry.

- **ID**: 07e08a12-870c-11eb-b5f9-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-17
- **Author**: Teoderick Contreras


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |


#### Search

```
`wineventlog_system` EventCode=7045 Service_Name IN ("SecurityCenterIBM", "WinCheckDRVs") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `clop_ransomware_known_service_name_filter`
```

#### Associated Analytic Story
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints.

#### Required field
* EventCode
* cmdline
* _time
* parent_process_name
* process_name
* OriginalFileName
* process_path


#### Kill Chain Phase
* Privilege Escalation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 100.0 | 100 | 100 |



#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log)


_version_: 1