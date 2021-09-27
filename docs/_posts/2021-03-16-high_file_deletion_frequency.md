---
title: "High File Deletion Frequency"
excerpt: "Data Destruction"
categories:
  - Endpoint
last_modified_at: 2021-03-16
toc: true
tags:
  - Anomaly
  - T1485
  - Data Destruction
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for high frequency of file deletion relative to process name and process id. These events usually happen when the ransomware tries to encrypt the files with the ransomware file extensions and sysmon treat the original files to be deleted as soon it was replace as encrypted data.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-16
- **Author**: Teoderick Contreras
- **ID**: 45b125c4-866f-11eb-a95a-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |



#### Search

```
`sysmon` EventCode=23 TargetFilename IN ("*\.cmd", "*\.ini","*\.gif", "*\.jpg", "*\.jpeg", "*\.db", "*\.ps1", "*\.doc*", "*\.xls*", "*\.ppt*", "*\.bmp","*\.zip", "*\.rar", "*\.7z", "*\.chm", "*\.png", "*\.log", "*\.vbs", "*\.js") 
| stats values(TargetFilename) as deleted_files min(_time) as firstTime max(_time) as lastTime count by Computer user EventCode Image ProcessID 
|where count >=100 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `high_file_deletion_frequency_filter`
```

#### Associated Analytic Story
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the deleted target file name, process name and process id  from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* EventCode
* TargetFilename
* Computer
* user
* Image
* ProcessID
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
user may delete bunch of pictures or files in a folder.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | High frequency file deletion activity detected on host $Computer$ |



#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/high_file_deletion_frequency.yml) \| *version*: **1**