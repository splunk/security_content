---
title: "Office Product Spawning Wmic"
excerpt: "Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-26
toc: true
tags:
  - TTP
  - T1566.001
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

The following detection identifies the latest behavior utilized by Ursnif malware family. This detection identifies any Windows Office Product spawning `wmic.exe`. In malicious instances, the command-line of `wmic.exe` will contain `wmic process call create`. In addition, Threat Research has released a detection identifying the use of `wmic process call create` on the command-line of `wmic.exe`. In this instance, we narrow our detection down to the Office suite as a parent process. During triage, review all file modifications. Capture and analyze any artifacts on disk. The Office Product, or `wmic.exe` will have reached out to a remote destination, capture and block the IPs or domain. Review additional parallel processes for further activity.

- **ID**: ffc236d6-a6c9-11eb-95f1-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-26
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","mspub.exe","visio.exe") Processes.process_name=wmic.exe by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `office_product_spawning_wmic_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* process_name
* process_id
* parent_process_name
* dest
* user
* parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
No false positives known. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference

* [https://app.any.run/tasks/fb894ab8-a966-4b72-920b-935f41756afd/](https://app.any.run/tasks/fb894ab8-a966-4b72-920b-935f41756afd/)
* [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_macros.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_macros.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_product_spawning_wmic.yml) \| *version*: **1**