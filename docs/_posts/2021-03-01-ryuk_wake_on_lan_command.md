---
title: "Ryuk Wake on LAN Command"
excerpt: "Command and Scripting Interpreter
, Windows Command Shell
"
categories:
  - Endpoint
last_modified_at: 2021-03-01
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Windows Command Shell
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This Splunk query identifies the use of Wake-on-LAN utilized by Ryuk ransomware. The Ryuk Ransomware uses the Wake-on-Lan feature to turn on powered off devices on a compromised network to have greater success encrypting them. This is a high fidelity indicator of Ryuk ransomware executing on an endpoint. Upon triage, isolate the endpoint. Additional file modification events will be within the users profile (\appdata\roaming) and in public directories (users\public\). Review all Scheduled Tasks on the isolated endpoint and across the fleet. Suspicious Scheduled Tasks will include a path to a unknown binary and those endpoints should be isolated until triaged.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-03-01
- **Author**: Michael Haag, Splunk
- **ID**: 538d0152-7aaa-11eb-beaa-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*8 LAN*" OR Processes.process="*9 REP*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `ryuk_wake_on_lan_command_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `ryuk_wake_on_lan_command_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Limited to no known false positives.

#### Associated Analytic story
* [Ryuk Ransomware](/stories/ryuk_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A process $process_name$ with wake on LAN commandline $process$ in host $dest$ |




#### Reference

* [https://www.bleepingcomputer.com/news/security/ryuk-ransomware-uses-wake-on-lan-to-encrypt-offline-devices/](https://www.bleepingcomputer.com/news/security/ryuk-ransomware-uses-wake-on-lan-to-encrypt-offline-devices/)
* [https://www.bleepingcomputer.com/news/security/ryuk-ransomware-now-self-spreads-to-other-windows-lan-devices/](https://www.bleepingcomputer.com/news/security/ryuk-ransomware-now-self-spreads-to-other-windows-lan-devices/)
* [https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-006.pdf](https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-006.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/ryuk/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/ryuk/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/ryuk_wake_on_lan_command.yml) \| *version*: **1**