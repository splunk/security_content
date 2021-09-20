---
title: "Remote WMI Command Attempt"
excerpt: "Windows Management Instrumentation"
categories:
  - Endpoint
last_modified_at: 2018-12-03
toc: true
tags:
  - TTP
  - T1047
  - Windows Management Instrumentation
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



#### Description

The following analytic identifies usage of `wmic.exe` spawning a local or remote process, identified by the `node` switch. During triage, review parallel processes for additional commands executed. Look for any file modifications before and after `wmic.exe` execution. In addition, identify the remote endpoint and confirm execution or file modifications. Contain and isolate the endpoint as needed.

- **ID**: 272df6de-61f1-4784-877c-1fbc3e2d0838
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-12-03
- **Author**: Rico Valdez, Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wmic.exe Processes.process=*node* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `remote_wmi_command_attempt_filter`
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model. Deprecated because duplicate of Remote Process Instantiation via WMI.

#### Required field
* _time
* Processes.user
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.parent_process
* Processes.parent_process_id
* Processes.process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators may use this legitimately to gather info from remote systems. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 36.0 | 60 | 60 |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.yaml)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log)


_version_: 3