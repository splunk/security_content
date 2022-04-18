---
title: "SchCache Change By App Connect And Create ADSI Object"
excerpt: "Domain Account
, Account Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-09-07
toc: true
toc_label: ""
tags:
  - Domain Account
  - Account Discovery
  - Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect an application try to connect and create ADSI Object to do LDAP query. Every time an application connects to the directory and attempts to create an ADSI object, the Active Directory Schema is checked for changes. If it has changed since the last connection, the schema is downloaded and stored in a cache on the local computer either in %LOCALAPPDATA%\Microsoft\Windows\SchCache or %systemroot%\SchCache. We found this a good anomaly use case to detect suspicious application like blackmatter ransomware that use ADS object api to execute ldap query. having a good list of ldap or normal AD query tool used within the network is a good start to reduce the noise.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: 991eb510-0fc6-11ec-82d3-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`sysmon` EventCode=11  TargetFilename = "*\\Windows\\SchCache\\*" TargetFilename = "*.sch*" NOT (Image IN ("*\\Windows\\system32\\mmc.exe")) 
|stats count min(_time) as firstTime max(_time) as lastTime by Image TargetFilename EventCode process_id  process_name Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schcache_change_by_app_connect_and_create_adsi_object_filter`
```

#### Macros
The SPL above uses the following Macros:
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **schcache_change_by_app_connect_and_create_adsi_object_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* TargetFilename
* EventCode
* process_id
* process_name
* Computer


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
normal application like mmc.exe and other ldap query tool may trigger this detections.

#### Associated Analytic story
* [blackMatter ransomware](/stories/blackmatter_ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | process $Image$ create a file $TargetFilename$ in host $Computer$ |


#### Reference

* [https://docs.microsoft.com/en-us/windows/win32/adsi/adsi-and-uac](https://docs.microsoft.com/en-us/windows/win32/adsi/adsi-and-uac)
* [https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/](https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/blackmatter_schcache/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/blackmatter_schcache/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/schcache_change_by_app_connect_and_create_adsi_object.yml) \| *version*: **1**