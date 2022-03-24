---
title: "Detect processes used for System Network Configuration Discovery"
excerpt: "System Network Configuration Discovery
"
categories:
  - Endpoint
last_modified_at: 2020-11-10
toc: true
toc_label: ""
tags:
  - System Network Configuration Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for fast execution of processes used for system network configuration discovery on the endpoint.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-11-10
- **Author**: Bhavin Patel, Splunk
- **ID**: a51bfe1a-94f0-48cc-b1e4-16ae10145893


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where NOT Processes.user IN ("","unknown") by Processes.dest Processes.process_name Processes.user _time 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| search `system_network_configuration_discovery_tools` 
| transaction dest connected=false maxpause=5m 
|where eventcount>=5 
| table firstTime lastTime dest user process_name process parent_process eventcount 
| `detect_processes_used_for_system_network_configuration_discovery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [system_network_configuration_discovery_tools](https://github.com/splunk/security_content/blob/develop/macros/system_network_configuration_discovery_tools.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_processes_used_for_system_network_configuration_discovery_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
You must be ingesting data that records registry activity from your hosts to populate the Endpoint data model in the processes node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or endpoint data sources, such as Sysmon. The data used for this search is usually generated via logs that report reads and writes to the registry or that are populated via Windows event logs, after enabling process tracking in your Windows audit settings.

#### Known False Positives
It is uncommon for normal users to execute a series of commands used for network discovery. System administrators often use scripts to execute these commands. These can generate false positives.

#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)


#### Kill Chain Phase
* Installation
* Command & Control
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 32.0 | 40 | 80 | An instance of $parent_process_name$ spawning multiple $process_name$ was identified on endpoint $dest$ by user $user$ typically not a normal behavior of the process. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/discovery_commands/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/discovery_commands/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_processes_used_for_system_network_configuration_discovery.yml) \| *version*: **2**