---
title: "Office Application Drop Executable"
excerpt: "Phishing
, Spearphishing Attachment
"
categories:
  - Endpoint
last_modified_at: 2021-09-13
toc: true
toc_label: ""
tags:
  - Phishing
  - Spearphishing Attachment
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious MS office application that drop or create executables or script in the host. This behavior is commonly seen in spear phishing office attachment where it drop malicious files or script to compromised the host. It might be some normal macro may drop script or tools as part of automation but still this behavior is reallly suspicious and not commonly seen in normal office application

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-13
- **Author**: Teoderick Contreras, Michael Haag Splunk
- **ID**: 73ce70c4-146d-11ec-9184-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name IN ("winword.exe","excel.exe","powerpnt.exe","mspub.exe","visio.exe","wordpad.exe","wordview.exe") by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*.exe","*.dll","*.pif","*.scr","*.js","*.vbs","*.vbe","*.ps1") by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.process_guid Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| rename process_guid as proc_guid 
| fields _time dest file_create_time file_name file_path process_name process_path process proc_guid] 
| dedup file_create_time 
| table dest, process_name, process, file_create_time, file_name, file_path, proc_guid 
| `office_application_drop_executable_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `office_application_drop_executable_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* TargetFilename
* ProcessGuid
* dest
* user_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Known False Positives
office macro for automation may do this behavior

#### Associated Analytic story
* [FIN7](/stories/fin7)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | process $process_name$ drops a file $TargetFilename$ in host $dest$ |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
* [https://attack.mitre.org/groups/G0046/](https://attack.mitre.org/groups/G0046/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_application_drop_executable.yml) \| *version*: **1**