---
title: "Suspicious SearchProtocolHost no Command Line Arguments"
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

The following analytic identifies searchprotocolhost.exe with no command line arguments. It is unusual for searchprotocolhost.exe to execute with no command line arguments present. This particular behavior is common with malicious software, including Cobalt Strike. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. searchprotocolhost.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **ID**: f52d2db8-31f9-4aa7-a176-25779effe55c
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-23
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |


#### Search

```
`sysmon` EventID=1 (process_name=searchprotocolhost.exe OR OriginalFileName=SearchProtocolHost.exe) 
| regex CommandLine="(searchprotocolhost\.exe.{0,4}$)" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, User, ParentImage,ParentCommandLine, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_searchprotocolhost_no_command_line_arguments_filter`
```

#### Associated Analytic Story
* [Cobalt Strike](/stories/cobalt_strike)


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

* [https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/SUSPICIOUS%20EXECUTION%20OF%20SEARCHPROTOCOLHOST%20(METHODOLOGY).ioc](https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/SUSPICIOUS%20EXECUTION%20OF%20SEARCHPROTOCOLHOST%20(METHODOLOGY).ioc)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_searchprotocolhost_no_command_line_arguments.yml) \| *version*: **1**