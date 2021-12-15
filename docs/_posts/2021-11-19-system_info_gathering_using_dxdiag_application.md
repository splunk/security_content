---
title: "System Info Gathering Using Dxdiag Application"
excerpt: "Gather Victim Host Information"
categories:
  - Endpoint
last_modified_at: 2021-11-19
toc: true
toc_label: ""
tags:
  - Gather Victim Host Information
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious dxdiag.exe process commandline can collect system info of the target host. This technique was seen in remcos, adversaries and other malware to collect information as part of recon or collection phase of attack. Even this behavior is rarely seen in a corporate network this commandline can be used by network administrator to audit host machine specification. Better to check what it did after it pipes out the result to a file for further processing.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: f92d74f2-4921-11ec-b685-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_dxdiag` AND Processes.process = "* /t *" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `system_info_gathering_using_dxdiag_application_filter`
```

#### Associated Analytic Story
* [Remcos](/stories/remcos)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
this commandline can be used by network administrator to audit host machine specification.filter is needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | dxdiag.exe process with commandline $process$ on $dest$ |




#### Reference

* [https://app.any.run/tasks/df0baf9f-8baf-4c32-a452-16562ecb19be/](https://app.any.run/tasks/df0baf9f-8baf-4c32-a452-16562ecb19be/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1592/host_info_dxdiag/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1592/host_info_dxdiag/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/system_info_gathering_using_dxdiag_application.yml) \| *version*: **1**