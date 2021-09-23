---
title: "Attempt To Stop Security Service"
excerpt: "Disable or Modify Tools"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
tags:
  - TTP
  - T1562.001
  - Disable or Modify Tools
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Installation
  - Actions on Objectives
---



[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for attempts to stop security-related services on the endpoint.

- **ID**: c8e349c6-b97c-486e-8949-bd7bcd1f3910
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name = net.exe OR  Processes.process_name = sc.exe) Processes.process="* stop *" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
|lookup security_services_lookup service as process OUTPUTNEW category, description 
| search category=security 
| `attempt_to_stop_security_service_filter`
```

#### Associated Analytic Story
* [Disabling Security Tools](/stories/disabling_security_tools)
* [Trickbot](/stories/trickbot)


#### How To Implement
You must be ingesting data that records the file-system activity from your hosts to populate the Endpoint file-system data-model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data. The search is shipped with a lookup file, `security_services.csv`, that can be edited to update the list of services to monitor. This lookup file can be edited directly where it lives in `$SPLUNK_HOME/etc/apps/DA-ESS-ContentUpdate/lookups`, or via the Splunk console. You should add the names of services an attacker might use on the command line and surround with asterisks (*****), so that they work properly when searching the command line. The file should be updated with the names of any services you would like to monitor for attempts to stop the service.,

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Installation
* Actions on Objectives


#### Known False Positives
None identified. Attempts to disable security-related services should be identified and understood.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 20.0 | 40 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified attempting to disable security services on endpoint $dest$ by user $user$. |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-14---disable-arbitrary-security-windows-service](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-14---disable-arbitrary-security-windows-service)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/attempt_to_stop_security_service.yml) \| *version*: **3**