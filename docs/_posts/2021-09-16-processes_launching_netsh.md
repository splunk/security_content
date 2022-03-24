---
title: "Processes launching netsh"
excerpt: "Disable or Modify System Firewall
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
toc_label: ""
tags:
  - Disable or Modify System Firewall
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for processes launching netsh.exe. Netsh is a command-line scripting utility that allows you to, either locally or remotely, display or modify the network configuration of a computer that is currently running. Netsh can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed. In this search, we are looking for processes spawned by netsh.exe and executing commands via the command line.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Josef Kuepker, Splunk
- **ID**: b89919ed-fe5f-492c-b139-95dbb162040e


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.004](https://attack.mitre.org/techniques/T1562/004/) | Disable or Modify System Firewall | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) AS Processes.process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_netsh` by Processes.parent_process_name Processes.parent_process Processes.original_file_name Processes.process_name Processes.user Processes.dest 
|`drop_dm_object_name("Processes")` 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
|`processes_launching_netsh_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_netsh](https://github.com/splunk/security_content/blob/develop/macros/process_netsh.yml)

Note that `processes_launching_netsh_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.user
* Processes.dest


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Some VPN applications are known to launch netsh.exe. Outside of these instances, it is unusual for an executable to launch netsh.exe and run commands.

#### Associated Analytic story
* [Netsh Abuse](/stories/netsh_abuse)
* [Disabling Security Tools](/stories/disabling_security_tools)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | A process $process_name$ that tries to execute netsh commandline $process$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/processes_launching_netsh.yml) \| *version*: **4**