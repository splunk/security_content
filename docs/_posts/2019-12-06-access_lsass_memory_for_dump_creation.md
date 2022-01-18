---
title: "Access LSASS Memory for Dump Creation"
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

Detect memory dumping of the LSASS process.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2019-12-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: fb4c31b0-13e8-4155-8aa5-24de4b8d6717


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`sysmon` EventCode=10 TargetImage=*lsass.exe CallTrace=*dbgcore.dll* OR CallTrace=*dbghelp.dll* 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, TargetImage, TargetProcessId, SourceImage, SourceProcessId 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `access_lsass_memory_for_dump_creation_filter` 
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
This search requires Sysmon Logs and a Sysmon configuration, which includes EventCode 10 for lsass.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Required field
* _time
* EventCode
* TargetImage
* CallTrace
* Computer
* TargetProcessId
* SourceImage
* SourceProcessId


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators can create memory dumps for debugging purposes, but memory dumps of the LSASS process would be unusual.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | process $SourceImage$ injected into $TargetImage$ and was attempted dump LSASS on $dest$. Adversaries tend to do this when trying to accesss credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). |




#### Reference

* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/access_lsass_memory_for_dump_creation.yml) \| *version*: **2**