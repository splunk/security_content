---
title: "Samsam Test File Write"
excerpt: "Data Encrypted for Impact"
categories:
  - Endpoint
last_modified_at: 2018-12-14
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for a file named &#34;test.txt&#34; written to the windows system directory tree, which is consistent with Samsam propagation.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-12-14
- **Author**: Rico Valdez, Splunk
- **ID**: 493a879d-519d-428f-8f57-a06a0fdc107e


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where Filesystem.file_path=*\\windows\\system32\\test.txt by Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `samsam_test_file_write_filter`
```

#### Associated Analytic Story
* [SamSam Ransomware](/stories/samsam_ransomware)


#### How To Implement
You must be ingesting data that records the file-system activity from your hosts to populate the Endpoint file-system data-model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Required field
* _time
* Filesystem.user
* Filesystem.dest
* Filesystem.file_name
* Filesystem.file_path


#### Kill Chain Phase
* Delivery


#### Known False Positives
No false positives have been identified.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 12.0 | 60 | 20 | A samsam ransomware test file creation in $file_path$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/sam_sam_note/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/sam_sam_note/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/samsam_test_file_write.yml) \| *version*: **1**