---
title: "Modification Of Wallpaper"
excerpt: "Defacement"
categories:
  - Endpoint
last_modified_at: 2021-06-02
toc: true
toc_label: ""
tags:
  - Defacement
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies suspicious modification of registry to deface or change the wallpaper of a compromised machines as part of its payload. This technique was commonly seen in ransomware like REVIL where it create a bitmap file contain a note that the machine was compromised and make it as a wallpaper.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: accb0712-c381-11eb-8e5b-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1491](https://attack.mitre.org/techniques/T1491/) | Defacement | Impact |

#### Search

```
`sysmon` EventCode =13  (TargetObject= "*\\Control Panel\\Desktop\\Wallpaper" AND Image != "*\\explorer.exe") OR (TargetObject= "*\\Control Panel\\Desktop\\Wallpaper" AND Details = "*\\temp\\*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Image TargetObject Details  Computer process_guid process_id user_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `modification_of_wallpaper_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)
* [Revil Ransomware](/stories/revil_ransomware)
* [BlackMatter Ransomware](/stories/blackmatter_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Image, TargetObject registry key, registry Details from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* EventCode
* Image
* TargetObject
* Details
* Computer
* process_guid
* process_id
* user_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
3rd party tool may used to changed the wallpaper of the machine


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 60 | 90 | Wallpaper modification on $dest$ |




#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/modification_of_wallpaper.yml) \| *version*: **1**