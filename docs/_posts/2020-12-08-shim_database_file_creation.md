---
title: "Shim Database File Creation"
excerpt: "Application Shimming"
categories:
  - Endpoint
last_modified_at: 2020-12-08
toc: true
tags:
  - TTP
  - T1546.011
  - Application Shimming
  - Privilege Escalation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



#### Description

This search looks for shim database files being written to default directories. The sdbinst.exe application is used to install shim database files (.sdb). According to Microsoft, a shim is a small library that transparently intercepts an API, changes the parameters passed, handles the operation itself, or redirects the operation elsewhere.

- **ID**: 6e4c4588-ba2f-42fa-97e6-9f6f548eaa33
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-12-08
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1546.011](https://attack.mitre.org/techniques/T1546/011/) | Application Shimming | Privilege Escalation, Persistence |


#### Search

```

| tstats `security_content_summariesonly` count values(Filesystem.action) values(Filesystem.file_hash) as file_hash values(Filesystem.file_path) as file_path  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path=*Windows\\AppPatch\\Custom* by Filesystem.file_name Filesystem.dest 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
|`drop_dm_object_name(Filesystem)` 
| `shim_database_file_creation_filter`
```

#### Associated Analytic Story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### How To Implement
You must be ingesting data that records the filesystem activity from your hosts to populate the Endpoint file-system data model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Required field
* _time
* Filesystem.file_hash
* Filesystem.file_path
* Filesystem.file_name
* Filesystem.dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Because legitimate shim files are created and used all the time, this event, in itself, is not suspicious. However, if there are other correlating events, it may warrant further investigation.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 56.0 | 70 | 80 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log)


_version_: 3