---
title: "CMD Echo Pipe - Escalation"
excerpt: "Windows Command Shell, Windows Service"
categories:
  - Endpoint
last_modified_at: 2021-05-20
toc: true
tags:
  - TTP
  - T1059.003
  - Windows Command Shell
  - Execution
  - T1543.003
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
  - Privilege Escalation
---



#### Description

This analytic identifies a common behavior by Cobalt Strike and other frameworks where the adversary will escalate privileges, either via `jump` (Cobalt Strike PTH) or `getsystem`, using named-pipe impersonation. A suspicious event will look like `cmd.exe /c echo 4sgryt3436 &gt; \\.\Pipe\5erg53`.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-20
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution || [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=cmd.exe OR Processes.process=*%comspec%*) (Processes.process=*echo* AND Processes.process=*pipe*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `cmd_echo_pipe___escalation_filter`
```

#### Associated Analytic Story
* [Cobalt Strike](_stories/cobalt_strike)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

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
* Exploitation
* Privilege Escalation


#### Known False Positives
Unknown. It is possible filtering may be required to ensure fidelity.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 64.0 | 80 | 80 |



#### Reference

* [https://redcanary.com/threat-detection-report/threats/cobalt-strike/](https://redcanary.com/threat-detection-report/threats/cobalt-strike/)
* [https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/elevate/namedpipe.c](https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/elevate/namedpipe.c)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)


_version_: 1