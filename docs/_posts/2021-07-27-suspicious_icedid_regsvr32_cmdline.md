---
title: "Suspicious IcedID Regsvr32 Cmdline"
excerpt: "Regsvr32"
categories:
  - Endpoint
last_modified_at: 2021-07-27
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
  - Exploitation
---



[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search is to detect a suspicious regsvr32 commandline &#34;-s&#34; to execute a dll files. This technique was seen in IcedID malware to execute its initial downloader dll that will download the 2nd stage loader that will download and decrypt the config payload.

- **ID**: c9ef7dc4-eeaf-11eb-b2b6-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-27
- **Author**: Teoderick Contreras,


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=regsvr32.exe Processes.process=*-s* by  Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_id Processes.parent_process_id Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_icedid_regsvr32_cmdline_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed regsvr32.exe may be used.

#### Required field
* _time
* process_name
* process
* parent_process_name
* parent_process
* process_id
* parent_process_id
* dest
* user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
minimal. but network operator can use this application to load dll.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | regsvr32 process $process_name$ with commandline $process$ in host $dest$ |



#### Reference

* [https://app.any.run/tasks/56680cba-2bbc-4b34-8633-5f7878ddf858/](https://app.any.run/tasks/56680cba-2bbc-4b34-8633-5f7878ddf858/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_icedid_regsvr32_cmdline.yml) \| *version*: **1**