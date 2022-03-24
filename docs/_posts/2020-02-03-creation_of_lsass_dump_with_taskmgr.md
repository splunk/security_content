---
title: "Creation of lsass Dump with Taskmgr"
excerpt: "LSASS Memory
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2020-02-03
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Detect the hands on keyboard behavior of Windows Task Manager creating a process dump of lsass.exe. Upon this behavior occurring, a file write/modification will occur in the users profile under \AppData\Local\Temp. The dump file, lsass.dmp, cannot be renamed, however if the dump occurs more than once, it will be named lsass (2).dmp.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-02-03
- **Author**: Michael Haag, Splunk
- **ID**: b2fbe95a-9c62-4c12-8a29-24b97e84c0cd


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`sysmon` EventID=11 process_name=taskmgr.exe TargetFilename=*lsass*.dmp 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, object_category, process_name, TargetFilename 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `creation_of_lsass_dump_with_taskmgr_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `creation_of_lsass_dump_with_taskmgr_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventID
* process_name
* TargetFilename
* Computer
* object_category


#### How To Implement
This search requires Sysmon Logs and a Sysmon configuration, which includes EventCode 11 for detecting file create of lsass.dmp. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Known False Positives
Administrators can create memory dumps for debugging purposes, but memory dumps of the LSASS process would be unusual.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | $process_name$ was identified on endpoint $Computer$ writing $TargetFilename$ to disk. This behavior is related to dumping credentials via Task Manager. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-5---dump-lsassexe-memory-using-windows-task-manager](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-5---dump-lsassexe-memory-using-windows-task-manager)
* [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)
* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/creation_of_lsass_dump_with_taskmgr.yml) \| *version*: **1**