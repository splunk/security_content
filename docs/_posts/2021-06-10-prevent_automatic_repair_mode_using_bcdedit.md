---
title: "Prevent Automatic Repair Mode using Bcdedit"
excerpt: "Inhibit System Recovery"
categories:
  - Endpoint
last_modified_at: 2021-06-10
toc: true
tags:
  - TTP
  - T1490
  - Inhibit System Recovery
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

This search is to detect a suspicious bcdedit.exe execution to ignore all failures. This technique was used by ransomware to prevent the compromise machine automatically boot in repair mode.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-10
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "bcdedit.exe" Processes.process = "*bootstatuspolicy*"  Processes.process = "*ignoreallfailures*" by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.dest Processes.user Processes.process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `prevent_automatic_repair_mode_using_bcdedit_filter`
```

#### Associated Analytic Story
* [Ransomware](_stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed bcdedit.exe may be used.

#### Required field
* _time
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.process_id
* Processes.process_guid


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Administrators may modify the boot configuration ignore failure during testing and debugging.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 56.0 | 70 | 80 |



#### Reference

* [https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_1_tamada-yamazaki-nakatsuru_en.pdf](https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_1_tamada-yamazaki-nakatsuru_en.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log)


_version_: 1