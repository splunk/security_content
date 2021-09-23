---
title: "System Information Discovery Detection"
excerpt: "System Information Discovery"
categories:
  - Endpoint
last_modified_at: 2020-10-12
toc: true
tags:
  - TTP
  - T1082
  - System Information Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect system information discovery techniques used by attackers to understand configurations of the system to further exploit it.

- **ID**: 8e99f89e-ae58-4ebc-bf52-ae0b1a277e72
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-10-12
- **Author**: Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*wmic* qfe*" OR Processes.process=*systeminfo* OR Processes.process=*hostname*) by Processes.user Processes.process_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| eventstats dc(process) as dc_processes_by_dest by dest 
| where dc_processes_by_dest > 2 
| stats values(process) min(firstTime) as firstTime max(lastTime) as lastTime by user, dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `system_information_discovery_detection_filter`
```

#### Associated Analytic Story
* [Discovery Techniques](/stories/discovery_techniques)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* Processes.process
* Processes.user
* Processes.process_name
* Processes.dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators debugging servers



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Potential system information discovery behavior on $dest$ by $User$ |



#### Reference

* [https://oscp.infosecsanyam.in/priv-escalation/windows-priv-escalation](https://oscp.infosecsanyam.in/priv-escalation/windows-priv-escalation)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1082/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1082/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/system_information_discovery_detection.yml) \| *version*: **1**