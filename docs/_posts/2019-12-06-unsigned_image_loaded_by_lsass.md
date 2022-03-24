---
title: "Unsigned Image Loaded by LSASS"
excerpt: "LSASS Memory
"
categories:
  - Deprecated
last_modified_at: 2019-12-06
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects loading of unsigned images by LSASS. Deprecated because too noisy.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2019-12-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: 56ef054c-76ef-45f9-af4a-a634695dcd65


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

#### Search

```
`sysmon` EventID=7 Image=*lsass.exe Signed=false 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, Image, ImageLoaded, Signed, SHA1 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `unsigned_image_loaded_by_lsass_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `unsigned_image_loaded_by_lsass_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
This search needs Sysmon Logs with a sysmon configuration, which includes EventCode 7 with lsass.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Known False Positives
Other tools could load images into LSASS for legitimate reason. But enterprise tools should always use signed DLLs.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/unsigned_image_loaded_by_lsass.yml) \| *version*: **1**