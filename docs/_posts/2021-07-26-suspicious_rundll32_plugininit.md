---
title: "Suspicious Rundll32 PluginInit"
excerpt: "Rundll32"
categories:
  - Endpoint
last_modified_at: 2021-07-26
toc: true
tags:
  - TTP
  - T1218.011
  - Rundll32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This search is to detect a suspicious rundll32.exe process with plugininit parameter. This technique is commonly seen in IceID malware to execute its initial dll stager to download another payload to the compromised machine.

- **ID**: 92d51712-ee29-11eb-b1ae-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-26
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=rundll32.exe Processes.process=*PluginInit* by  Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_id Processes.parent_process_id Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_rundll32_plugininit_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

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
third party application may used this dll export name to execute function.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 42.0 | 60 | 70 |



#### Reference

* [https://threatpost.com/icedid-banking-trojan-surges-emotet/165314/](https://threatpost.com/icedid-banking-trojan-surges-emotet/165314/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log)


_version_: 1