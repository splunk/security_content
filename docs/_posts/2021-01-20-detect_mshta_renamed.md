---
title: "Detect mshta renamed"
excerpt: "Mshta"
categories:
  - Endpoint
last_modified_at: 2021-01-20
toc: true
tags:
  - TTP
  - T1218.005
  - Mshta
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---



#### Description

The following analytic identifies renamed instances of mshta.exe executing. Mshta.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64. This analytic utilizes the internal name of the PE to identify if is the legitimate mshta binary. Further analysis should be performed to review the executed content and validation it is the real mshta.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-20
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |


#### Search

```
`sysmon` EventID=1 (OriginalFileName=mshta.exe AND process_name!=mshta.exe) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `detect_mshta_renamed_filter`
```

#### Associated Analytic Story
* [Suspicious MSHTA Activity](_stories/suspicious_mshta_activity)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* EventID
* OriginalFileName
* process_name
* Computer
* User
* parent_process_name
* process_path
* CommandLine


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Although unlikely, some legitimate applications may use a moved copy of mshta.exe, but never renamed, triggering a false positive.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference

* [https://github.com/redcanaryco/AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses)
* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log)


_version_: 1