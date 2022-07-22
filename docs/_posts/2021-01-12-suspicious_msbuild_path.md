---
title: "Suspicious msbuild path"
excerpt: "Masquerading
, Trusted Developer Utilities Proxy Execution
, Rename System Utilities
, MSBuild
"
categories:
  - Endpoint
last_modified_at: 2021-01-12
toc: true
toc_label: ""
tags:
  - Masquerading
  - Trusted Developer Utilities Proxy Execution
  - Rename System Utilities
  - MSBuild
  - Defense Evasion
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

The following analytic identifies msbuild.exe executing from a non-standard path. Msbuild.exe is natively found in C:\Windows\Microsoft.NET\Framework\v4.0.30319 and C:\Windows\Microsoft.NET\Framework64\v4.0.30319. Instances of Visual Studio will run a copy of msbuild.exe. A moved instance of MSBuild is suspicious, however there are instances of build applications that will move or use a copy of MSBuild.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-01-12
- **Author**: Michael Haag, Splunk
- **ID**: f5198224-551c-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1127](https://attack.mitre.org/techniques/T1127/) | Trusted Developer Utilities Proxy Execution | Defense Evasion |

| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

| [T1127.001](https://attack.mitre.org/techniques/T1127/001/) | MSBuild | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_msbuild` AND (Processes.process_path!=c:\\windows\\microsoft.net\\framework*\\v*\\*) by Processes.dest Processes.original_file_name Processes.parent_process Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `suspicious_msbuild_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_msbuild](https://github.com/splunk/security_content/blob/develop/macros/process_msbuild.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `suspicious_msbuild_path_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Some legitimate applications may use a moved copy of msbuild.exe, triggering a false positive. Baselining of MSBuild.exe usage is recommended to better understand it's path usage. Visual Studio runs an instance out of a path that will need to be filtered on.

#### Associated Analytic story
* [Trusted Developer Utilities Proxy Execution MSBuild](/stories/trusted_developer_utilities_proxy_execution_msbuild)
* [Cobalt Strike](/stories/cobalt_strike)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Msbuild.exe ran from an uncommon path on $dest$ execyted by $user$ |




#### Reference

* [https://lolbas-project.github.io/lolbas/Binaries/Msbuild/](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_msbuild_path.yml) \| *version*: **2**