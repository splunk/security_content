---
title: "Detect Regsvcs with No Command Line Arguments"
excerpt: "Regsvcs/Regasm"
categories:
  - Endpoint
last_modified_at: 2021-02-12
toc: true
tags:
  - TTP
  - T1218.009
  - Regsvcs/Regasm
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

The following analytic identifies regsvcs.exe with no command line arguments. This particular behavior occurs when another process injects into regsvcs.exe, no command line arguments will be present. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. Regasm.exe are natively found in C:\Windows\Microsoft.NET\Framework\v*\regasm|regsvcs.exe and C:\Windows\Microsoft.NET\Framework64\v*\regasm|regsvcs.exe.

- **ID**: 6b74d578-a02e-4e94-a0d1-39440d0bf254
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-12
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.009](https://attack.mitre.org/techniques/T1218/009/) | Regsvcs/Regasm | Defense Evasion |


#### Search

```
`sysmon` EventID=1 (process_name=regsvcs.exe OR OriginalFileName=RegSvcs.exe) 
| regex CommandLine="(regsvcs\.exe.{0,4}$)" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, User, ParentImage,ParentCommandLine, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_regsvcs_with_no_command_line_arguments_filter`
```

#### Associated Analytic Story
* [Suspicious Regsvcs Regasm Activity](/stories/suspicious_regsvcs_regasm_activity)


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
* OriginalFileName
* process_path
* Computer


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, limited instances of regsvcs.exe may cause a false positive. Filter based endpoint usage, command line arguments, or process lineage.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 49.0 | 70 | 70 |



#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/](https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_regsvcs_with_no_command_line_arguments.yml) \| *version*: **1**