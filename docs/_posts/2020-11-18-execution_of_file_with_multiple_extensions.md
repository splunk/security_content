---
title: "Execution of File with Multiple Extensions"
excerpt: "Masquerading, Rename System Utilities"
categories:
  - Endpoint
last_modified_at: 2020-11-18
toc: true
toc_label: ""
tags:
  - Masquerading
  - Defense Evasion
  - Rename System Utilities
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for processes launched from files that have double extensions in the file name. This is typically done to obscure the &#34;real&#34; file extension and make it appear as though the file being accessed is a data file, as opposed to executable content.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-11-18
- **Author**: Rico Valdez, Splunk
- **ID**: b06a555e-dce0-417d-a2eb-28a5d8d66ef7


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process = *.doc.exe OR Processes.process = *.htm.exe OR Processes.process = *.html.exe OR Processes.process = *.txt.exe OR Processes.process = *.pdf.exe OR Processes.process = *.doc.exe by Processes.dest Processes.user Processes.process Processes.parent_process 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| `execution_of_file_with_multiple_extensions_filter`
```

#### Associated Analytic Story
* [Windows File Extension and Association Abuse](/stories/windows_file_extension_and_association_abuse)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model in the processes node.

#### Required field
* _time
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | process $process$ have double extensions in the file name is executed on $dest$ by $user$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/execution_of_file_with_multiple_extensions.yml) \| *version*: **3**