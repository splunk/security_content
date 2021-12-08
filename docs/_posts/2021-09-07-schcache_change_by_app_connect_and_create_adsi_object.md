---
title: "SchCache Change By App Connect And Create ADSI Object"
excerpt: "Domain Account, Account Discovery"
categories:
  - Endpoint
last_modified_at: 2021-09-07
toc: true
toc_label: ""
tags:
  - Domain Account
  - Discovery
  - Account Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect an application try to connect and create ADSI Object to do LDAP query. Every time an application connects to the directory and attempts to create an ADSI object, the Active Directory Schema is checked for changes. If it has changed since the last connection, the schema is downloaded and stored in a cache on the local computer either in %LOCALAPPDATA%\Microsoft\Windows\SchCache or %systemroot%\SchCache. We found this a good anomaly use case to detect suspicious application like blackmatter ransomware that use ADS object api to execute ldap query. having a good list of ldap or normal AD query tool used within the network is a good start to reduce the noise.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: 991eb510-0fc6-11ec-82d3-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

#### Search

```
`sysmon` EventCode=11  TargetFilename = "*\\Windows\\SchCache\\*" TargetFilename = "*.sch*" NOT (Image IN ("*\\Windows\\system32\\mmc.exe")) 
|stats count min(_time) as firstTime max(_time) as lastTime by Image TargetFilename EventCode process_id  process_name Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schcache_change_by_app_connect_and_create_adsi_object_filter`
```

#### Associated Analytic Story
* [blackMatter ransomware](/stories/blackmatter_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Image
* TargetFilename
* EventCode
* process_id
* process_name
* Computer


#### Kill Chain Phase
* Exploitation


#### Known False Positives
normal application like mmc.exe and other ldap query tool may trigger this detections.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | process $Image$ create a file $TargetFilename$ in host $Computer$ |




#### Reference

* [https://docs.microsoft.com/en-us/windows/win32/adsi/adsi-and-uac](https://docs.microsoft.com/en-us/windows/win32/adsi/adsi-and-uac)
* [https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/](https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/blackmatter_schcache/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/blackmatter_schcache/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/schcache_change_by_app_connect_and_create_adsi_object.yml) \| *version*: **1**