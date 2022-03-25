---
title: "Process Deleting Its Process File Path"
excerpt: "Indicator Removal on Host
"
categories:
  - Endpoint
last_modified_at: 2022-02-18
toc: true
toc_label: ""
tags:
  - Indicator Removal on Host
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection is to identify a suspicious process that tries to delete the process file path related to its process. This technique is known to be defense evasion once a certain condition of malware is satisfied or not. Clop ransomware use this technique where it will try to delete its process file path using a .bat command if the keyboard layout is not the layout it tries to infect.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-18
- **Author**: Teoderick Contreras
- **ID**: f7eda4bc-871c-11eb-b110-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

#### Search

```
`sysmon` EventCode=1 CommandLine = "* /c *" CommandLine = "* del*" Image = "*\\cmd.exe" 
| eval result = if(like(process,"%".parent_process."%"), "Found", "Not Found") 
| stats min(_time) as firstTime max(_time) as lastTime count by Computer user ParentImage ParentCommandLine Image CommandLine EventCode ProcessID result 
| where result = "Found" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `process_deleting_its_process_file_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `process_deleting_its_process_file_path_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* EventCode
* Computer
* user
* ParentImage
* ParentCommandLine
* Image
* cmdline
* ProcessID
* result
* _time


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
unknown

#### Associated Analytic story
* [Clop Ransomware](/stories/clop_ransomware)
* [Remcos](/stories/remcos)
* [WhisperGate](/stories/whispergate)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 60.0 | 60 | 100 | A process $Image$ tries to delete its process path in commandline $cmdline$ as part of defense evasion in host $Computer$ |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/process_deleting_its_process_file_path.yml) \| *version*: **2**