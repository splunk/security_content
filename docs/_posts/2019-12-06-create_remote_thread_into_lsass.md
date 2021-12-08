---
title: "Create Remote Thread into LSASS"
excerpt: "LSASS Memory, OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2019-12-06
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - Credential Access
  - OS Credential Dumping
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect remote thread creation into LSASS consistent with credential dumping.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2019-12-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: 67d4dbef-9564-4699-8da8-03a151529edc


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`sysmon` EventID=8 TargetImage=*lsass.exe 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, EventCode, TargetImage, TargetProcessId 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `create_remote_thread_into_lsass_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
This search needs Sysmon Logs with a Sysmon configuration, which includes EventCode 8 with lsass.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Required field
* _time
* EventID
* TargetImage
* Computer
* EventCode
* TargetImage
* TargetProcessId
* dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Other tools can access LSASS for legitimate reasons and generate an event. In these cases, tweaking the search may help eliminate noise.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | A process has created a remote thread into $TargetImage$ on $dest$. This behavior is indicative of credential dumping and should be investigated. |




#### Reference

* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/create_remote_thread_into_lsass.yml) \| *version*: **1**