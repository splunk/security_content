---
title: "Detect Regsvcs with No Command Line Arguments"
excerpt: "Signed Binary Proxy Execution, Regsvcs/Regasm"
categories:
  - Endpoint
last_modified_at: 2021-09-20
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Regsvcs/Regasm
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies regsvcs.exe with no command line arguments. This particular behavior occurs when another process injects into regsvcs.exe, no command line arguments will be present. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. Regasm.exe are natively found in C:\Windows\Microsoft.NET\Framework\v*\regasm|regsvcs.exe and C:\Windows\Microsoft.NET\Framework64\v*\regasm|regsvcs.exe.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-20
- **Author**: Michael Haag, Splunk
- **ID**: 6b74d578-a02e-4e94-a0d1-39440d0bf254


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.009](https://attack.mitre.org/techniques/T1218/009/) | Regsvcs/Regasm | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where `process_regsvcs` by _time span=1h  Processes.process_id Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| regex process="(regsvcs\.exe.{0,4}$)"
| `detect_regsvcs_with_no_command_line_arguments_filter`
```

#### Associated Analytic Story
* [Suspicious Regsvcs Regasm Activity](/stories/suspicious_regsvcs_regasm_activity)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, limited instances of regsvcs.exe may cause a false positive. Filter based endpoint usage, command line arguments, or process lineage.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | The process $process_name$ was spawned by $parent_process_name$ without any command-line arguments on $dest$ by $user$. |




#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/](https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_regsvcs_with_no_command_line_arguments.yml) \| *version*: **2**