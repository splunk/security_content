---
title: "Detect Credential Dumping through LSASS access"
excerpt: "LSASS Memory"
categories:
  - Endpoint
last_modified_at: 2019-12-03
toc: true
tags:
  - TTP
  - T1003.001
  - LSASS Memory
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



#### Description

This search looks for reading lsass memory consistent with credential dumping.

- **ID**: 2c365e57-4414-4540-8dc0-73ab10729996
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2019-12-03
- **Author**: Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |


#### Search

```
`sysmon` EventCode=10 TargetImage=*lsass.exe (GrantedAccess=0x1010 OR GrantedAccess=0x1410) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SourceImage, SourceProcessId, TargetImage, TargetProcessId, EventCode, GrantedAccess 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_credential_dumping_through_lsass_access_filter` 
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)


#### How To Implement
This search needs Sysmon Logs and a sysmon configuration, which includes EventCode 10 with lsass.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

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


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
The activity may be legitimate. Other tools can access lsass for legitimate reasons, and it&#39;s possible this event could be generated in those cases. In these cases, false positives should be fairly obvious and you may need to tweak the search to eliminate noise.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)


_version_: 3