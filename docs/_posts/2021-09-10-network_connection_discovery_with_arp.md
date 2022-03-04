---
title: "Network Connection Discovery With Arp"
excerpt: "System Network Connections Discovery"
categories:
  - Endpoint
last_modified_at: 2021-09-10
toc: true
toc_label: ""
tags:
  - System Network Connections Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `arp.exe` utilized to get a listing of network connections on a compromised system. Red Teams and adversaries alike may use arp.exe for situational awareness and Active Directory Discovery.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-10
- **Author**: Mauricio Velazco, Splunk
- **ID**: ae008c0f-83bd-4ed4-9350-98d4328e15d2


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1049](https://attack.mitre.org/techniques/T1049/) | System Network Connections Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="arp.exe") (Processes.process=*-a*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `network_connection_discovery_with_arp_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `network_connection_discovery_with_arp_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Administrators or power users may use this command for troubleshooting.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Network Connection discovery on $dest$ by $user$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/network_connection_discovery_with_arp.yml) \| *version*: **1**