---
title: "Windows Service Created Within Public Path"
excerpt: "Create or Modify System Process, Windows Service"
categories:
  - Endpoint
last_modified_at: 2021-11-22
toc: true
toc_label: ""
tags:
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytc uses Windows Event Id 7045, `New Service Was Installed`, to identify the creation of a Windows Service where the service binary path is located in public paths. This behavior could represent the installation of a malicious service. Red Teams and adversaries alike may create malicious Services for lateral movement or remote code execution

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-11-22
- **Author**: Mauricio Velazco, Splunk
- **ID**: 3abb2eda-4bb8-11ec-9ae4-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

#### Search

```
`wineventlog_system` EventCode=7045  Service_File_Name = "*\.exe" NOT (Service_File_Name IN ("C:\\Windows\\*", "C:\\Program File*", "C:\\Programdata\\*", "%systemroot%\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_service_created_within_public_path_filter`
```

#### Associated Analytic Story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints.

#### Required field
* EventCode
* Service_File_Name
* Service_Type
* _time
* Service_Name
* Service_Start_Type


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Legitimate applications may install services with uncommon services paths.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | A Windows Service $Service_File_Name$ with a public path was created on $ComputerName |




#### Reference

* [https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)
* [https://pentestlab.blog/2020/07/21/lateral-movement-services/](https://pentestlab.blog/2020/07/21/lateral-movement-services/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement_suspicious_path/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement_suspicious_path/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_service_created_within_public_path.yml) \| *version*: **1**