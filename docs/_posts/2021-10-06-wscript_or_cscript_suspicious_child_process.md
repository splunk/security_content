---
title: "Wscript Or Cscript Suspicious Child Process"
excerpt: "Process Injection
, Create or Modify System Process
, Parent PID Spoofing
, Access Token Manipulation
"
categories:
  - Endpoint
last_modified_at: 2021-10-06
toc: true
toc_label: ""
tags:
  - Process Injection
  - Create or Modify System Process
  - Parent PID Spoofing
  - Access Token Manipulation
  - Defense Evasion
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies a suspicious spawned process by WScript or CScript process. This technique was a common technique used by adversaries and malware to execute different LOLBIN, other scripts like PowerShell or spawn a suspended process to inject its code as a defense evasion. This TTP may detect some normal script that using several application tool that are in the list of the child process it detects but a good pivot and indicator that a script is may execute suspicious code.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1f35e1da-267b-11ec-90a9-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

| [T1134.004](https://attack.mitre.org/techniques/T1134/004/) | Parent PID Spoofing | Defense Evasion, Privilege Escalation |

| [T1134](https://attack.mitre.org/techniques/T1134/) | Access Token Manipulation | Defense Evasion, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("cscript.exe", "wscript.exe") Processes.process_name IN ("regsvr32.exe", "rundll32.exe","winhlp32.exe","certutil.exe","msbuild.exe","cmd.exe","powershell*","wmic.exe","mshta.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wscript_or_cscript_suspicious_child_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `wscript_or_cscript_suspicious_child_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Administrators may create vbs or js script that use several tool as part of its execution. Filter as needed.

#### Associated Analytic story
* [FIN7](/stories/fin7)
* [Remcos](/stories/remcos)
* [Unusual Processes](/stories/unusual_processes)
* [WhisperGate](/stories/whispergate)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | wscript or cscript parent process spawned $process_name$ in $dest$ |




#### Reference

* [https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120](https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wscript_or_cscript_suspicious_child_process.yml) \| *version*: **1**