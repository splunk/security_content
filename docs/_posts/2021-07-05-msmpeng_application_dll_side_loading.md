---
title: "Msmpeng Application DLL Side Loading"
excerpt: "DLL Side-Loading"
categories:
  - Endpoint
last_modified_at: 2021-07-05
toc: true
tags:
  - TTP
  - T1574.002
  - DLL Side-Loading
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious creation of msmpeng.exe or mpsvc.dll in non default windows defender folder. This technique was seen couple days ago with revil ransomware in Kaseya Supply chain. The approach is to drop an old version of msmpeng.exe to load the actual payload name as mspvc.dll which will load the revil ransomware to the compromise machine

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: 8bb3f280-dd9b-11eb-84d5-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | DLL Side-Loading | Persistence, Privilege Escalation, Defense Evasion |


#### Search

```

|tstats `security_content_summariesonly` values(Filesystem.file_path) as file_path count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name = "msmpeng.exe" OR Filesystem.file_name = "mpsvc.dll")  AND Filesystem.file_path != "*\\Program Files\\windows defender\\*" by Filesystem.file_create_time Filesystem.process_id  Filesystem.file_name Filesystem.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `msmpeng_application_dll_side_loading_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)
* [Revil Ransomware](/stories/revil_ransomware)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.

#### Required field
* _time
* Filesystem.file_create_time
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.user
* Filesystem.file_path


#### Kill Chain Phase
* Exploitation


#### Known False Positives
quite minimal false positive expected.




#### Reference

* [https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers](https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets//malware/revil/msmpeng_side/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets//malware/revil/msmpeng_side/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/msmpeng_application_dll_side_loading.yml) \| *version*: **1**