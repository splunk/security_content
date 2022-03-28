---
title: "Detect Renamed RClone"
excerpt: "Automated Exfiltration
"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
toc_label: ""
tags:
  - Automated Exfiltration
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the usage of `rclone.exe`, renamed, being used to exfiltrate data to a remote destination. RClone has been used by multiple ransomware groups to exfiltrate data. In many instances, it will be downloaded from the legitimate site and executed accordingly. During triage, isolate the endpoint and begin to review parallel processes for additional behavior. At this stage, the adversary may have staged data to be exfiltrated.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Splunk
- **ID**: 6dca1124-b3ec-11eb-9328-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Exfiltration |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.original_file_name=rclone.exe AND Processes.process_name!=rclone.exe) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_rclone_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_renamed_rclone_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives should be limited as this analytic identifies renamed instances of `rclone.exe`. Filter as needed if there is a legitimate business use case.

#### Associated Analytic story
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | The following $process_name$ has been identified as renamed, spawning from $parent_process_name$ on $dest$ by $user$. |




#### Reference

* [https://redcanary.com/blog/rclone-mega-extortion/](https://redcanary.com/blog/rclone-mega-extortion/)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)
* [https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_renamed_rclone.yml) \| *version*: **2**