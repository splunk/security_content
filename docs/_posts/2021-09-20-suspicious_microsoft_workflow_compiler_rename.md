---
title: "Suspicious microsoft workflow compiler rename"
excerpt: "Masquerading
, Trusted Developer Utilities Proxy Execution
, Rename System Utilities
"
categories:
  - Endpoint
last_modified_at: 2021-09-20
toc: true
toc_label: ""
tags:
  - Masquerading
  - Trusted Developer Utilities Proxy Execution
  - Rename System Utilities
  - Defense Evasion
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a renamed instance of microsoft.workflow.compiler.exe. Microsoft.workflow.compiler.exe is natively found in C:\Windows\Microsoft.NET\Framework64\v4.0.30319 and is rarely utilized. When investigating, identify the executed code on disk and review. A spawned child process from microsoft.workflow.compiler.exe is uncommon. In any instance, microsoft.workflow.compiler.exe spawning from an Office product or any living off the land binary is highly suspect.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-20
- **Author**: Michael Haag, Splunk
- **ID**: f0db4464-55d9-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1127](https://attack.mitre.org/techniques/T1127/) | Trusted Developer Utilities Proxy Execution | Defense Evasion |

| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_microsoftworkflowcompiler` by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_microsoft_workflow_compiler_rename_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_microsoftworkflowcompiler](https://github.com/splunk/security_content/blob/develop/macros/process_microsoftworkflowcompiler.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `suspicious_microsoft_workflow_compiler_rename_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Although unlikely, some legitimate applications may use a moved copy of microsoft.workflow.compiler.exe, triggering a false positive.

#### Associated Analytic story
* [Trusted Developer Utilities Proxy Execution](/stories/trusted_developer_utilities_proxy_execution)
* [Cobalt Strike](/stories/cobalt_strike)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Suspicious renamed microsoft.workflow.compiler.exe binary ran on $dest$ by $user$ |




#### Reference

* [https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/](https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-6---microsoftworkflowcompilerexe-payload-execution](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-6---microsoftworkflowcompilerexe-payload-execution)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_microsoft_workflow_compiler_rename.yml) \| *version*: **3**