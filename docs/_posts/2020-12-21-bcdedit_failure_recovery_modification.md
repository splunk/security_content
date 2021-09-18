---
title: "BCDEdit Failure Recovery Modification"
excerpt: "Inhibit System Recovery"
categories:
  - Endpoint
last_modified_at: 2020-12-21
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
  - Actions on Objectives
---



#### Description

This search looks for flags passed to bcdedit.exe modifications to the built-in Windows error recovery boot configurations. This is typically used by ransomware to prevent recovery.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-12-21
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = bcdedit.exe Processes.process="*recoveryenabled*" (Processes.process="* no*") by Processes.process_name Processes.process Processes.parent_process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `bcdedit_failure_recovery_modification_filter`
```

#### Associated Analytic Story
* [Ryuk Ransomware](_stories/ryuk_ransomware)
* [Ransomware](_stories/ransomware)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints to populate the Endpoint data model in the Processes node. Tune based on parent process names.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators may modify the boot configuration.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 100 | 80 |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-4---windows---disable-windows-recovery-console-repair](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-4---windows---disable-windows-recovery-console-repair)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log)


_version_: 1