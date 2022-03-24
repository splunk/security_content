---
title: "Detect Credential Dumping through LSASS access"
excerpt: "LSASS Memory
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2019-12-03
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for reading lsass memory consistent with credential dumping.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2019-12-03
- **Author**: Patrick Bareiss, Splunk
- **ID**: 2c365e57-4414-4540-8dc0-73ab10729996


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`sysmon` EventCode=10 TargetImage=*lsass.exe (GrantedAccess=0x1010 OR GrantedAccess=0x1410) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SourceImage, SourceProcessId, TargetImage, TargetProcessId, EventCode, GrantedAccess 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_credential_dumping_through_lsass_access_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `detect_credential_dumping_through_lsass_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* TargetImage
* GrantedAccess
* Computer
* SourceImage
* SourceProcessId
* TargetImage
* TargetProcessId


#### How To Implement
This search needs Sysmon Logs and a sysmon configuration, which includes EventCode 10 with lsass.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Known False Positives
The activity may be legitimate. Other tools can access lsass for legitimate reasons, and it's possible this event could be generated in those cases. In these cases, false positives should be fairly obvious and you may need to tweak the search to eliminate noise.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The $source_image$ has attempted access to read $TargetImage$ was identified on endpoint $Computer$, this is indicative of credential dumping and should be investigated. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_credential_dumping_through_lsass_access.yml) \| *version*: **3**