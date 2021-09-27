---
title: "Suspicious Regsvr32 Register Suspicious Path"
excerpt: "Regsvr32"
categories:
  - Endpoint
last_modified_at: 2021-01-28
toc: true
tags:
  - TTP
  - T1218.010
  - Regsvr32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may abuse Regsvr32.exe to proxy execution of malicious code by using non-standard file extensions to load malciious DLLs. Upon investigating, look for network connections to remote destinations (internal or external). Review additional parrallel processes and child processes for additional activity.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-28
- **Author**: Michael Haag, Splunk
- **ID**: 62732736-6250-11eb-ae93-0242ac130002


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_regsvr32` (Processes.process=*appdata* OR Processes.process=*programdata* OR Processes.process=*windows\temp*) (Processes.process!=*.dll Processes.process!=*.ax Processes.process!=*.ocx) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.original_file_name Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `suspicious_regsvr32_register_suspicious_path_filter`
```

#### Associated Analytic Story
* [Suspicious Regsvr32 Activity](/stories/suspicious_regsvr32_activity)
* [Iceid](/stories/iceid)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints, to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model. Tune the query by filtering additional extensions found to be used by  legitimate processes. To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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
* Actions on Objectives


#### Known False Positives
Limited false positives with the query restricted to specified paths. Add more world writeable paths as tuning continues.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicious $Processes.process_path.file_path$ process potentially loading malicious code |



#### Reference

* [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
* [https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5](https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5)
* [https://any.run/report/f29a7d2ecd3585e1e4208e44bcc7156ab5388725f1d29d03e7699da0d4598e7c/0826458b-5367-45cf-b841-c95a33a01718](https://any.run/report/f29a7d2ecd3585e1e4208e44bcc7156ab5388725f1d29d03e7699da0d4598e7c/0826458b-5367-45cf-b841-c95a33a01718)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.010/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.010/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_regsvr32_register_suspicious_path.yml) \| *version*: **2**