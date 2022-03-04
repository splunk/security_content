---
title: "Windows NirSoft AdvancedRun"
excerpt: "Tool
"
categories:
  - Endpoint
last_modified_at: 2022-01-21
toc: true
toc_label: ""
tags:

  - Tool
  - Resource Development
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of AdvancedRun.exe. AdvancedRun.exe has similar capabilities as other remote programs like psexec. AdvancedRun may also ingest a configuration file with all settings defined and perform its activity. The analytic is written in a way to identify a renamed binary and also the common command-line arguments.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-21
- **Author**: Michael Haag, Splunk
- **ID**: bb4f3090-7ae4-11ec-897f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Tool | Resource Development |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=advancedrun.exe OR Processes.original_file_name=advancedrun.exe) Processes.process IN ("*EXEFilename*","*/cfg*","*RunAs*", "*WindowState*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.original_file_name Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `windows_nirsoft_advancedrun_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_nirsoft_advancedrun_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives should be limited as it is specific to AdvancedRun. Filter as needed based on legitimate usage.

#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)
* [Ransomware](/stories/ransomware)
* [WhisperGate](/stories/whispergate)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 60.0 | 60 | 100 | An instance of advancedrun.exe, $process_name$, was spawned by $parent_process_name$ on $dest$ by $user$. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [http://www.nirsoft.net/utils/advanced_run.html](http://www.nirsoft.net/utils/advanced_run.html)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_nirsoft_advancedrun.yml) \| *version*: **1**