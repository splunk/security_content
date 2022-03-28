---
title: "WBAdmin Delete System Backups"
excerpt: "Inhibit System Recovery
"
categories:
  - Endpoint
last_modified_at: 2021-01-22
toc: true
toc_label: ""
tags:
  - Inhibit System Recovery
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for flags passed to wbadmin.exe (Windows Backup Administrator Tool) that delete backup files. This is typically used by ransomware to prevent recovery.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-01-22
- **Author**: Michael Haag, Splunk
- **ID**: cd5aed7e-5cea-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wbadmin.exe Processes.process="*delete*" AND (Processes.process="*catalog*" OR Processes.process="*systemstatebackup*") by Processes.process_name Processes.process Processes.parent_process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `wbadmin_delete_system_backups_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `wbadmin_delete_system_backups_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints to populate the Endpoint data model in the Processes node. Tune based on parent process names.

#### Known False Positives
Administrators may modify the boot configuration.

#### Associated Analytic story
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | System backups deletion on $dest$ |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md)
* [https://thedfirreport.com/2020/10/08/ryuks-return/](https://thedfirreport.com/2020/10/08/ryuks-return/)
* [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wbadmin_delete_system_backups.yml) \| *version*: **1**