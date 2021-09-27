---
title: "Detect Renamed 7-Zip"
excerpt: "Archive via Utility"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
tags:
  - Hunting
  - T1560.001
  - Archive via Utility
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exfiltration
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies renamed 7-Zip usage using Sysmon. At this stage of an attack, review parallel processes and file modifications for data that is staged or potentially have been exfiltrated. This analytic utilizes the OriginalFileName to capture the renamed process. During triage, validate this is the legitimate version of `7zip` by reviewing the PE metadata. In addition, review parallel processes for further suspicious behavior.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Splunk
- **ID**: 4057291a-b8cf-11eb-95fe-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.original_file_name=7z*.exe AND Processes.process_name!=7z*.exe) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_7_zip_filter`
```

#### Associated Analytic Story
* [Collection and Staging](/stories/collection_and_staging)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

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
* Exfiltration


#### Known False Positives
Limited false positives, however this analytic will need to be modified for each environment if Sysmon is not used.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | The following $process_name$ has been identified as renamed, spawning from $parent_process_name$ on $dest$ by $user$. |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_renamed_7-zip.yml) \| *version*: **2**