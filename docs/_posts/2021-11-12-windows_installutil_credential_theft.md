---
title: "Windows InstallUtil Credential Theft"
excerpt: "InstallUtil, Signed Binary Proxy Execution"
categories:
  - Endpoint
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - InstallUtil
  - Defense Evasion
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the Windows InstallUtil.exe binary loading `vaultcli.dll` and Samlib.dll`. This technique may be used to execute code to bypassing application control and capture credentials by utilizing a tool like MimiKatz. \
When `InstallUtil.exe` is used in a malicous manner, the path to an executable on the filesystem is typically specified. Take note of the parent process. In a suspicious instance, this will be spawned from a non-standard process like `Cmd.exe`, `PowerShell.exe` or `Explorer.exe`. \
If used by a developer, typically this will be found with multiple command-line switches/arguments and spawn from Visual Studio. \
During triage review resulting network connections, file modifications, and parallel processes. Capture any artifacts and review further.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-12
- **Author**: Michael Haag, Splunk
- **ID**: ccfeddec-43ec-11ec-b494-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | InstallUtil | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

#### Search

```
`sysmon` EventCode=7  process_name=installutil.exe ImageLoaded IN ("*\\samlib.dll", "*\\vaultcli.dll") 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, process_name, ImageLoaded, OriginalFileName, process_id 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_installutil_credential_theft_filter`
```

#### Associated Analytic Story
* [Signed Binary Proxy Execution InstallUtil](/stories/signed_binary_proxy_execution_installutil)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and module loads from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

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
* Exploitation
* Privilege Escalation


#### Known False Positives
Typically this will not trigger as by it&#39;s very nature InstallUtil does not need credentials. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ loading samlib.dll and vaultcli.dll to potentially capture credentials in memory. |




#### Reference

* [https://gist.github.com/xorrior/bbac3919ca2aef8d924bdf3b16cce3d0](https://gist.github.com/xorrior/bbac3919ca2aef8d924bdf3b16cce3d0)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_installutil_credential_theft.yml) \| *version*: **1**