---
title: "Windows InstallUtil URL in Command Line"
excerpt: "InstallUtil
, Signed Binary Proxy Execution
"
categories:
  - Endpoint
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - InstallUtil
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the Windows InstallUtil.exe binary passing a HTTP request on the command-line. This technique may be used to download and execute code while bypassing application control. \
When `InstallUtil.exe` is used in a malicous manner, the path to an executable on the filesystem is typically specified. Take note of the parent process. In a suspicious instance, this will be spawned from a non-standard process like `Cmd.exe`, `PowerShell.exe` or `Explorer.exe`. \
If used by a developer, typically this will be found with multiple command-line switches/arguments and spawn from Visual Studio. \
During triage review resulting network connections, file modifications, and parallel processes. Capture any artifacts and review further.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-11-12
- **Author**: Michael Haag, Splunk
- **ID**: 28e06670-43df-11ec-a569-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | InstallUtil | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_installutil` Processes.process IN ("*http://*","*https://*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_installutil_url_in_command_line_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_installutil](https://github.com/splunk/security_content/blob/develop/macros/process_installutil.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_installutil_url_in_command_line_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Limited false positives should be present as InstallUtil is not typically used to download remote files. Filter as needed based on Developers requirements.

#### Associated Analytic story
* [Signed Binary Proxy Execution InstallUtil](/stories/signed_binary_proxy_execution_installutil)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ passing a URL on the command-line. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)
* [https://gist.github.com/DanielRTeixeira/0fd06ec8f041f34a32bf5623c6dd479d](https://gist.github.com/DanielRTeixeira/0fd06ec8f041f34a32bf5623c6dd479d)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_installutil_url_in_command_line.yml) \| *version*: **1**