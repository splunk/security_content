---
title: "System User Discovery With Whoami"
excerpt: "System Owner/User Discovery"
categories:
  - Endpoint
last_modified_at: 2021-09-13
toc: true
toc_label: ""
tags:
  - System Owner/User Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `whoami.exe` without any arguments. This windows native binary prints out the current logged user. Red Teams and adversaries alike may leverage `whoami.exe` to identify system users on a compromised endpoint for situational awareness and Active Directory Discovery.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-13
- **Author**: Mauricio Velazco, Splunk
- **ID**: 894fc43e-6f50-47d5-a68b-ee9ee23e18f4


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="whoami.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `system_user_discovery_with_whoami_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `system_user_discovery_with_whoami_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
| 15.0 | 30 | 50 | System user discovery on $dest$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/system_user_discovery_with_whoami.yml) \| *version*: **1**