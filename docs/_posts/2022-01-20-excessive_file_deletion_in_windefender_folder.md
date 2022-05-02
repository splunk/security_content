---
title: "Excessive File Deletion In WinDefender Folder"
excerpt: "Data Destruction
"
categories:
  - Endpoint
last_modified_at: 2022-01-20
toc: true
toc_label: ""
tags:
  - Data Destruction
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify excessive file deletion events in the Windows Defender folder. This technique was seen in the WhisperGate malware campaign in which adversaries abused Nirsofts advancedrun.exe to gain administrative privilege to then execute PowerShell commands to delete files within the Windows Defender application folder. This behavior is a good indicator the offending process is trying to corrupt a Windows Defender installation.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: b5baa09a-7a05-11ec-8da4-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`sysmon` EventCode=23 TargetFilename = "*\\ProgramData\\Microsoft\\Windows Defender*" 
| stats values(TargetFilename) as deleted_files min(_time) as firstTime max(_time) as lastTime count by user EventCode Image ProcessID Computer 
|where count >=50 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_file_deletion_in_windefender_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **excessive_file_deletion_in_windefender_folder_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* TargetFilename
* Computer
* user
* Image
* ProcessID


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, TargetFilename, and ProcessID executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Windows Defender AV updates may cause this alert. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [WhisperGate](/stories/whispergate)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | High frequency file deletion activity detected on host $Computer$ |


#### Reference

* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/excessive_file_del_in_windefender_dir/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/excessive_file_del_in_windefender_dir/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_file_deletion_in_windefender_folder.yml) \| *version*: **1**