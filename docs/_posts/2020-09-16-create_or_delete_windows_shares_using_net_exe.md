---
title: "Create or delete windows shares using net exe"
excerpt: "Indicator Removal on Host
, Network Share Connection Removal
"
categories:
  - Endpoint
last_modified_at: 2020-09-16
toc: true
toc_label: ""
tags:
  - Indicator Removal on Host
  - Network Share Connection Removal
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the creation or deletion of hidden shares using net.exe.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-09-16
- **Author**: Bhavin Patel, Splunk
- **ID**: 743a322c-9a68-4a0f-9c17-85d9cce2a27c


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

| [T1070.005](https://attack.mitre.org/techniques/T1070/005/) | Network Share Connection Removal | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.user) as user values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_net` by Processes.process Processes.process_name Processes.original_file_name Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| search process=*share* 
| `create_or_delete_windows_shares_using_net_exe_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [process_net](https://github.com/splunk/security_content/blob/develop/macros/process_net.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `create_or_delete_windows_shares_using_net_exe_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Administrators often leverage net.exe to create or delete network shares. You should verify that the activity was intentional and is legitimate.

#### Associated Analytic story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ enumerating Windows file shares. |




#### Reference

* [https://attack.mitre.org/techniques/T1070/005](https://attack.mitre.org/techniques/T1070/005)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.005/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/create_or_delete_windows_shares_using_net_exe.yml) \| *version*: **6**