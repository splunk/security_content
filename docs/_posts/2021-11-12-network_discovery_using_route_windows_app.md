---
title: "Network Discovery Using Route Windows App"
excerpt: "System Network Configuration Discovery, Internet Connection Discovery"
categories:
  - Endpoint
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - System Network Configuration Discovery
  - Discovery
  - Internet Connection Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic look for a spawned process of route.exe windows application. Adversaries and red teams alike abuse this application the recon or do a network discovery on a target host. but one possible false positive might be an automated tool used by a system administator or a powershell script in amazon ec2 config services.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: dd83407e-439f-11ec-ab8e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Discovery |

| [T1016.001](https://attack.mitre.org/techniques/T1016/001/) | Internet Connection Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_route` by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `network_discovery_using_route_windows_app_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
A network operator or systems administrator may utilize an automated host discovery application that may generate false positives or an amazon ec2 script that uses this application. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | Network Connection discovery on $dest$ by $user$ |




#### Reference

* [https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/#](https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/#)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/network_discovery_using_route_windows_app.yml) \| *version*: **1**