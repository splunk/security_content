---
title: "Linux Doas Tool Execution"
excerpt: "Sudo and Sudo Caching
, Abuse Elevation Control Mechanism
"
categories:
  - Endpoint
last_modified_at: 2022-01-05
toc: true
toc_label: ""
tags:
  - Sudo and Sudo Caching
  - Abuse Elevation Control Mechanism
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

This analytic is to detect the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does. This tool is developed as a minimalistic alternative to sudo application. This tool can be abused advesaries, attacker or malware to gain elevated privileges to the targeted or compromised host. On the other hand this can also be executed by administrator for a certain task that needs admin rights. In this case filter is needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-01-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: d5a62490-6e09-11ec-884e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Sudo and Sudo Caching | Defense Evasion, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "doas" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_doas_tool_execution_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_doas_tool_execution_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
Administrator or network operator can execute this command. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A doas $process_name$ with commandline $process$ was executed on $dest$ |




#### Reference

* [https://wiki.gentoo.org/wiki/Doas](https://wiki.gentoo.org/wiki/Doas)
* [https://www.makeuseof.com/how-to-install-and-use-doas/](https://www.makeuseof.com/how-to-install-and-use-doas/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/doas_exec/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/doas_exec/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_doas_tool_execution.yml) \| *version*: **1**