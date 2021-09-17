---
title: "Suspicious GPUpdate no Command Line Arguments"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-02-23
toc: true
tags:
  - TTP
  - T1055
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

#### Description

The following analytic identifies gpupdate.exe with no command line arguments. It is unusual for gpupdate.exe to execute with no command line arguments present. This particular behavior is common with malicious software, including Cobalt Strike. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. gpupdate.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2021-02-23
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |


#### Search

```
`sysmon` EventID=1 (process_name=gpupdate.exe OR OriginalFileName=GPUpdate.exe) 
| regex CommandLine="(gpupdate\.exe.{0,4}$)" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, User, ParentImage,ParentCommandLine, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_gpupdate_no_command_line_arguments_filter`
```

#### Associated Analytic Story
* [Cobalt Strike](_stories/cobalt_strike)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* EventID
* process_name
* OriginalFileName
* CommandLine
* dest
* User
* ParentImage
* ParentCommandLine
* process_path


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Limited false positives may be present in small environments. Tuning may be required based on parent process.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 49.0 | 70 | 70 |



#### Reference

* [https://raw.githubusercontent.com/xx0hcd/Malleable-C2-Profiles/0ef8cf4556e26f6d4190c56ba697c2159faa5822/crimeware/trick_ryuk.profile](https://raw.githubusercontent.com/xx0hcd/Malleable-C2-Profiles/0ef8cf4556e26f6d4190c56ba697c2159faa5822/crimeware/trick_ryuk.profile)
* [https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/](https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)


_version_: 1