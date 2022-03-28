---
title: "Suspicious Linux Discovery Commands"
excerpt: "Unix Shell
"
categories:
  - Endpoint
last_modified_at: 2021-12-06
toc: true
toc_label: ""
tags:
  - Unix Shell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search, detects execution of suspicious bash commands from various commonly leveraged bash scripts like (AutoSUID, LinEnum, LinPeas) to perform discovery of possible paths of privilege execution, password files, vulnerable directories, executables and file permissions on a Linux host.\
The search logic specifically looks for high number of distinct commands run in a short period of time.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-06
- **Author**: Bhavin Patel, Splunk
- **ID**: 0edd5112-56c9-11ec-b990-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) values(Processes.process_name) values(Processes.parent_process_name) dc(Processes.process) as distinct_commands dc(Processes.process_name) as distinct_process_names min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where [
|inputlookup linux_tool_discovery_process.csv 
| rename process as Processes.process 
|table Processes.process] by _time span=5m Processes.user Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| where distinct_commands > 40 AND distinct_process_names > 3
| `suspicious_linux_discovery_commands_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `suspicious_linux_discovery_commands_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.user
* Processes.process_name


#### How To Implement
This detection search is based on Splunk add-on for Microsoft Sysmon-Linux.(https://splunkbase.splunk.com/app/6176/). Please install this add-on to parse fields correctly and execute detection search. Consider customizing the time window and threshold values according to your environment.

#### Known False Positives
Unless an administrator is using these commands to troubleshoot or audit a system, the execution of these commands should be monitored.

#### Associated Analytic story
* [Linux Post-Exploitation](/stories/linux_post-exploitation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | Suspicious Linux Discovery Commands detected on $dest$ |




#### Reference

* [https://attack.mitre.org/matrices/enterprise/linux/](https://attack.mitre.org/matrices/enterprise/linux/)
* [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)
* [https://github.com/IvanGlinkin/AutoSUID](https://github.com/IvanGlinkin/AutoSUID)
* [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/linux_discovery_tools/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/linux_discovery_tools/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_linux_discovery_commands.yml) \| *version*: **1**