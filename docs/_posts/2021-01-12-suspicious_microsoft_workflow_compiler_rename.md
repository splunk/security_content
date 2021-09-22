---
title: "Suspicious microsoft workflow compiler rename"
excerpt: "Trusted Developer Utilities Proxy Execution, Rename System Utilities"
categories:
  - Endpoint
last_modified_at: 2021-01-12
toc: true
tags:
  - TTP
  - T1127
  - Trusted Developer Utilities Proxy Execution
  - Defense Evasion
  - T1036.003
  - Rename System Utilities
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

The following analytic identifies a renamed instance of microsoft.workflow.compiler.exe. Microsoft.workflow.compiler.exe is natively found in C:\Windows\Microsoft.NET\Framework64\v4.0.30319 and is rarely utilized. When investigating, identify the executed code on disk and review. A spawned child process from microsoft.workflow.compiler.exe is uncommon. In any instance, microsoft.workflow.compiler.exe spawning from an Office product or any living off the land binary is highly suspect.

- **ID**: f0db4464-55d9-11eb-ae93-0242ac130002
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-12
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1127](https://attack.mitre.org/techniques/T1127/) | Trusted Developer Utilities Proxy Execution | Defense Evasion || [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |


#### Search

```
`sysmon` EventID=1 (OriginalFileName=microsoft.workflow.compiler.exe OR process_name=microsoft.workflow.compiler.exe) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `suspicious_microsoft_workflow_compiler_rename_filter`
```

#### Associated Analytic Story
* [Trusted Developer Utilities Proxy Execution](/stories/trusted_developer_utilities_proxy_execution)
* [Cobalt Strike](/stories/cobalt_strike)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)


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
Although unlikely, some legitimate applications may use a moved copy of microsoft.workflow.compiler.exe, triggering a false positive.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference

* [https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/](https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-6---microsoftworkflowcompilerexe-payload-execution](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-6---microsoftworkflowcompilerexe-payload-execution)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_microsoft_workflow_compiler_rename.yml) \| *version*: **1**