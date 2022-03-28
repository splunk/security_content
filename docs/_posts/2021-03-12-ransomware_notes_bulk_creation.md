---
title: "Ransomware Notes bulk creation"
excerpt: "Data Encrypted for Impact
"
categories:
  - Endpoint
last_modified_at: 2021-03-12
toc: true
toc_label: ""
tags:
  - Data Encrypted for Impact
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytics identifies a big number of instance of ransomware notes (filetype e.g .txt, .html, .hta) file creation to the infected machine. This behavior is a good sensor if the ransomware note filename is quite new for security industry or the ransomware note filename is not in your ransomware lookup table list for monitoring.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-03-12
- **Author**: Teoderick Contreras
- **ID**: eff7919a-8330-11eb-83f8-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact |

#### Search

```
`sysmon` EventCode=11 file_name IN ("*\.txt","*\.html","*\.hta") 
|bin _time span=10s 
| stats min(_time) as firstTime max(_time) as lastTime dc(TargetFilename) as unique_readme_path_count values(TargetFilename) as list_of_readme_path by Computer Image file_name 
| where unique_readme_path_count >= 15 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `ransomware_notes_bulk_creation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `ransomware_notes_bulk_creation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* EventCode
* file_name
* _time
* TargetFilename
* Computer
* Image
* user


#### How To Implement
You must be ingesting data that records the filesystem activity from your hosts to populate the Endpoint file-system data model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Known False Positives
unknown

#### Associated Analytic story
* [Clop Ransomware](/stories/clop_ransomware)
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [BlackMatter Ransomware](/stories/blackmatter_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | A high frequency file creation of $file_name$ in different file path in host $Computer$ |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/ransomware_notes_bulk_creation.yml) \| *version*: **1**