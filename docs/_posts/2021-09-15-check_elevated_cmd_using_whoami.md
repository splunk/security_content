---
title: "Check Elevated CMD using whoami"
excerpt: "System Owner/User Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-09-15
toc: true
toc_label: ""
tags:
  - System Owner/User Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious whoami execution to check if the cmd or shell instance process is with elevated privileges. This technique was seen in FIN7 js implant where it execute this as part of its data collection to the infected machine to check if the running shell cmd process is elevated or not. This TTP is really a good alert for known attacker that recon on the targetted host. This command is not so commonly executed by a normal user or even an admin to check if a process is elevated.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-09-15
- **Author**: Teoderick Contreras, Splunk
- **ID**: a9079b18-1633-11ec-859c-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  Processes.process = "*whoami*" Processes.process = "*/group*" Processes.process = "* find *" Processes.process = "*12288*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `check_elevated_cmd_using_whoami_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `check_elevated_cmd_using_whoami_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process_id
* Processes.process
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Known False Positives
unknown

#### Associated Analytic story
* [FIN7](/stories/fin7)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | Process name $process_name$ with commandline $process$ in $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_js_2/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_js_2/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/check_elevated_cmd_using_whoami.yml) \| *version*: **1**