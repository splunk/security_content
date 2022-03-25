---
title: "Known Services Killed by Ransomware"
excerpt: "Inhibit System Recovery
"
categories:
  - Endpoint
last_modified_at: 2021-06-04
toc: true
toc_label: ""
tags:
  - Inhibit System Recovery
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects a suspicioous termination of known services killed by ransomware before encrypting files in a compromised machine. This technique is commonly seen in most of ransomware now a days to avoid exception error while accessing the targetted files it wants to encrypts because of the open handle of those services to the targetted file.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-06-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: 3070f8e0-c528-11eb-b2a0-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |

#### Search

```
`wineventlog_system` EventCode=7036 Message IN ("*Volume Shadow Copy*","*VSS*", "*backup*", "*sophos*", "*sql*", "*memtas*", "*mepocs*", "*veeam*", "*svc$*") Message="*service entered the stopped state*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message dest Type 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `known_services_killed_by_ransomware_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)

Note that `known_services_killed_by_ransomware_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* dest
* Type


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the 7036 EventCode ScManager in System audit Logs from your endpoints.

#### Known False Positives
Admin activities or installing related updates may do a sudden stop to list of services we monitor.

#### Associated Analytic story
* [Ransomware](/stories/ransomware)
* [BlackMatter Ransomware](/stories/blackmatter_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | Known services $Message$ terminated by a potential ransomware on $dest$ |




#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf3/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf3/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/known_services_killed_by_ransomware.yml) \| *version*: **1**