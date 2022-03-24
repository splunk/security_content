---
title: "Detect RClone Command-Line Usage"
excerpt: "Automated Exfiltration
"
categories:
  - Endpoint
last_modified_at: 2021-11-29
toc: true
toc_label: ""
tags:
  - Automated Exfiltration
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies commonly used command-line arguments used by `rclone.exe` to initiate a file transfer. Some arguments were negated as they are specific to the configuration used by adversaries. In particular, an adversary may list the files or directories of the remote file share using `ls` or `lsd`, which is not indicative of malicious behavior. During triage, at this stage of a ransomware event, exfiltration is about to occur or has already. Isolate the endpoint and continue investigating by review file modifications and parallel processes.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-11-29
- **Author**: Michael Haag, Splunk
- **ID**: 32e0baea-b3f1-11eb-a2ce-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Exfiltration |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_rclone` Processes.process IN ("*copy*", "*mega*", "*pcloud*", "*ftp*", "*--config*", "*--progress*", "*--no-check-certificate*", "*--ignore-existing*", "*--auto-confirm*", "*--transfers*", "*--multi-thread-streams*")  by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
|  `security_content_ctime(lastTime)` 
| `detect_rclone_command_line_usage_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_rclone](https://github.com/splunk/security_content/blob/develop/macros/process_rclone.yml)

Note that `detect_rclone_command-line_usage_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id
* Processes.original_file_name


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited as this is restricted to the Rclone process name. Filter or tune the analytic as needed.

#### Associated Analytic story
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to connect to a remote cloud service to move files or folders. |




#### Reference

* [https://redcanary.com/blog/rclone-mega-extortion/](https://redcanary.com/blog/rclone-mega-extortion/)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)
* [https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
* [https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_rclone_command-line_usage.yml) \| *version*: **2**