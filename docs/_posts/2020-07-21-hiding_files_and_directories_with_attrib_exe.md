---
title: "Hiding Files And Directories With Attrib exe"
excerpt: "File and Directory Permissions Modification
, Windows File and Directory Permissions Modification
"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - File and Directory Permissions Modification
  - Windows File and Directory Permissions Modification
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Attackers leverage an existing Windows binary, attrib.exe, to mark specific as hidden by using specific flags so that the victim does not see the file.  The search looks for specific command-line arguments to detect the use of attrib.exe to hide files.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 6e5a3ae4-90a3-462d-9aa6-0119f638c0f1


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |

| [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | Windows File and Directory Permissions Modification | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=attrib.exe (Processes.process=*+h*) by Processes.parent_process Processes.process_name Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)`
| `hiding_files_and_directories_with_attrib_exe_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `hiding_files_and_directories_with_attrib_exe_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.process_name
* Processes.parent_process
* Processes.user
* Processes.dest


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
Some applications and users may legitimately use attrib.exe to interact with the files. 

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | Attrib.exe with +h flag to hide files on $dest$ executed by $user$ is detected. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/hiding_files_and_directories_with_attrib_exe.yml) \| *version*: **4**