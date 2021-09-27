---
title: "Detect Regasm with no Command Line Arguments"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies regasm.exe with no command line arguments. This particular behavior occurs when another process injects into regasm.exe, no command line arguments will be present. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. Regasm.exe are natively found in C:\Windows\Microsoft.NET\Framework\v*\regasm|regsvcs.exe and C:\Windows\Microsoft.NET\Framework64\v*\regasm|regsvcs.exe.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-12
- **Author**: Michael Haag, Splunk
- **ID**: c3bc1430-04e7-4178-835f-047d8e6e97df


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.009](https://attack.mitre.org/techniques/T1218/009/) | Regsvcs/Regasm | Defense Evasion |


#### Search

```
`sysmon` EventID=1 (process_name=regasm.exe OR OriginalFileName=RegAsm.exe) 
| regex CommandLine="(regasm\.exe.{0,4}$)" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, User, ParentImage,ParentCommandLine, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_regasm_with_no_command_line_arguments_filter`
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
* process_path
* Computer


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, limited instances of regasm.exe or may cause a false positive. Filter based endpoint usage, command line arguments, or process lineage.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | The process $process_name$ was spawned by $parent_image$ without any command-line arguments on $dest$ by $user$. |



#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regasm/](https://lolbas-project.github.io/lolbas/Binaries/Regasm/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_regasm_with_no_command_line_arguments.yml) \| *version*: **1**