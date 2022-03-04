---
title: "Overwriting Accessibility Binaries"
excerpt: "Event Triggered Execution, Accessibility Features"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Event Triggered Execution
  - Privilege Escalation
  - Persistence
  - Accessibility Features
  - Privilege Escalation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Microsoft Windows contains accessibility features that can be launched with a key combination before a user has logged in. An adversary can modify or replace these programs so they can get a command prompt or backdoor without logging in to the system. This search looks for modifications to these binaries.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: 13c2f6c3-10c5-4deb-9ba1-7c4460ebe4ae


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Privilege Escalation, Persistence |

| [T1546.008](https://attack.mitre.org/techniques/T1546/008/) | Accessibility Features | Privilege Escalation, Persistence |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where (Filesystem.file_path=*\\Windows\\System32\\sethc.exe* OR Filesystem.file_path=*\\Windows\\System32\\utilman.exe* OR Filesystem.file_path=*\\Windows\\System32\\osk.exe* OR Filesystem.file_path=*\\Windows\\System32\\Magnify.exe* OR Filesystem.file_path=*\\Windows\\System32\\Narrator.exe* OR Filesystem.file_path=*\\Windows\\System32\\DisplaySwitch.exe* OR Filesystem.file_path=*\\Windows\\System32\\AtBroker.exe*) by Filesystem.file_name Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `overwriting_accessibility_binaries_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `overwriting_accessibility_binaries_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.dest
* Filesystem.file_path
* Filesystem.file_name
* Filesystem.dest


#### How To Implement
You must be ingesting data that records the filesystem activity from your hosts to populate the Endpoint file-system data model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Known False Positives
Microsoft may provide updates to these binaries. Verify that these changes do not correspond with your normal software update cycle.

#### Associated Analytic story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | A suspicious file modification or replace in $file_path$  in host $dest$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.008/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.008/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/overwriting_accessibility_binaries.yml) \| *version*: **4**