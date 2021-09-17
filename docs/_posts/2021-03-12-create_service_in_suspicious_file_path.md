---
title: "Create Service In Suspicious File Path"
excerpt: "Service Execution"
categories:
  - Endpoint
last_modified_at: 2021-03-12
toc: true
tags:
  - TTP
  - T1569.002
  - Service Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Privilege Escalation
---

#### Description

This detection is to identify a creation of &#34;user mode service&#34; where the service file path is located in non-common service folder in windows.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-12
- **Author**: Teoderick Contreras


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |


#### Search

```
 `wineventlog_system` EventCode=7045  Service_File_Name = "*\.exe" NOT (Service_File_Name IN ("C:\\Windows\\*", "C:\\Program File*", "C:\\Programdata\\*", "%systemroot%\\*")) Service_Type = "user mode service" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `create_service_in_suspicious_file_path_filter`
```

#### Associated Analytic Story
* [Clop Ransomware](_stories/clop_ransomware)


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
* Privilege Escalation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 56.0 | 70 | 80 |



#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log)


_version_: 1