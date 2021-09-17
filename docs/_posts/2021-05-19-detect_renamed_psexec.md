---
title: "Detect Renamed PSExec"
excerpt: "Service Execution"
categories:
  - Endpoint
last_modified_at: 2021-05-19
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
  - Exploitation
  - Lateral Movement
  - Execution
---

#### Description

The following analytic identifies renamed instances of `PsExec.exe` being utilized on an endpoint. Most instances, it is highly probable to capture `Psexec.exe` or other SysInternal utility usage with the command-line argument of `-accepteula`. In this instance, we are using `OriginalFileName` from Sysmon to identify `PsExec` usage. During triage, validate this is the legitimate version of `PsExec` by review the PE metadata. In addition, review parallel processes for further suspicious behavior.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-19
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |


#### Search

```
`sysmon` EventID=1 (OriginalFileName=psexec.c process_name!=psexec.exe process_name!=PsExec64.exe) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine Product 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_psexec_filter`
```

#### Associated Analytic Story
* [SamSam Ransomware](_stories/samsam_ransomware)
* [DHS Report TA18-074A](_stories/dhs_report_ta18-074a)
* [HAFNIUM Group](_stories/hafnium_group)
* [DarkSide Ransomware](_stories/darkside_ransomware)
* [Lateral Movement](_stories/lateral_movement)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Required field
* _time
* dest
* User
* parent_process_name
* process_name
* OriginalFileName
* process_path
* CommandLine
* Product


#### Kill Chain Phase
* Exploitation
* Lateral Movement
* Execution


#### Known False Positives
Limited false positives should be present. It is possible some third party applications may use older versions of PsExec, filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 27.0 | 30 | 90 |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.yaml)
* [https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/](https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-sysmon.log)


_version_: 1