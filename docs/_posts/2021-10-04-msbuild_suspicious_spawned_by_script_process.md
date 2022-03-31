---
title: "MSBuild Suspicious Spawned By Script Process"
excerpt: "MSBuild
, Trusted Developer Utilities Proxy Execution
"
categories:
  - Endpoint
last_modified_at: 2021-10-04
toc: true
toc_label: ""
tags:
  - MSBuild
  - Trusted Developer Utilities Proxy Execution
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious child process of MSBuild spawned by Windows Script Host - cscript or wscript. This behavior or event are commonly seen and used by malware or adversaries to execute malicious msbuild process using malicious script in the compromised host. During triage, review parallel processes and identify any file modifications. MSBuild may load a script from the same path without having command-line arguments.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: 213b3148-24ea-11ec-93a2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1127.001](https://attack.mitre.org/techniques/T1127/001/) | MSBuild | Defense Evasion |

| [T1127](https://attack.mitre.org/techniques/T1127/) | Trusted Developer Utilities Proxy Execution | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe", "cscript.exe") AND `process_msbuild` by Processes.dest Processes.parent_process Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `msbuild_suspicious_spawned_by_script_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_msbuild](https://github.com/splunk/security_content/blob/develop/macros/process_msbuild.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `msbuild_suspicious_spawned_by_script_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.parent_process
* Processes.parent_process_name
* Processes.process_name
* Processes.original_file_name
* Processes.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited as developers do not spawn MSBuild via a WSH.

#### Associated Analytic story
* [Trusted Developer Utilities Proxy Execution MSBuild](/stories/trusted_developer_utilities_proxy_execution_msbuild)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Msbuild.exe process spawned by $parent_process_name$ on $dest$ executed by $user$ |




#### Reference

* [https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#](https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/regsvr32_silent/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/regsvr32_silent/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/msbuild_suspicious_spawned_by_script_process.yml) \| *version*: **1**