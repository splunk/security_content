---
title: "Suspicious Rundll32 Rename"
excerpt: "Rundll32, Rename System Utilities"
categories:
  - Endpoint
last_modified_at: 2021-02-04
toc: true
tags:
  - TTP
  - T1218.011
  - Rundll32
  - Defense Evasion
  - T1036.003
  - Rename System Utilities
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



#### Description

The following analytic identifies renamed instances of rundll32.exe executing. rundll32.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64. During investigation, validate it is the legitimate rundll32.exe executing and what script content it is loading. This query relies on the OriginalFileName from Sysmon, or internal name from the PE meta data. Expand the query as needed by looking for specific command line arguments outlined in other analytics.

- **ID**: 7360137f-abad-473e-8189-acbdaa34d114
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-04
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion || [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |


#### Search

```
`sysmon` EventID=1 OriginalFileName=RUNDLL32.EXE NOT process_name=rundll32.exe 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `suspicious_rundll32_rename_filter`
```

#### Associated Analytic Story
* [Suspicious Rundll32 Activity](/stories/suspicious_rundll32_activity)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

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
* Actions on Objectives


#### Known False Positives
Although unlikely, some legitimate applications may use a moved copy of rundll32, triggering a false positive.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference

* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log)


_version_: 1