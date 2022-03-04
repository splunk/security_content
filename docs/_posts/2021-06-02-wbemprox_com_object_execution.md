---
title: "Wbemprox COM Object Execution"
excerpt: "Signed Binary Proxy Execution
, CMSTP
"
categories:
  - Endpoint
last_modified_at: 2021-06-02
toc: true
toc_label: ""
tags:

  - Signed Binary Proxy Execution
  - CMSTP
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search is designed to detect potential malicious process loading COM object to wbemprox.dll,

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9d911ce0-c3be-11eb-b177-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.003](https://attack.mitre.org/techniques/T1218/003/) | CMSTP | Defense Evasion |

#### Search

```
`sysmon` EventCode=7  ImageLoaded IN ("*\\fastprox.dll", "*\\wbemprox.dll", "*\\wbemcomn.dll") NOT (process_name IN ("wmiprvse.exe", "WmiApSrv.exe", "unsecapp.exe")) NOT(Image IN("*\\windows\\*","*\\program files*", "*\\wbem\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded process_name Computer EventCode Signed ProcessId Hashes IMPHASH 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wbemprox_com_object_execution_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `wbemprox_com_object_execution_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* ImageLoaded
* process_name
* Computer
* EventCode
* Signed
* ProcessId
* Hashes
* IMPHASH


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
legitimate process that are not in the exception list may trigger this event.

#### Associated Analytic story
* [Ransomware](/stories/ransomware)
* [Revil Ransomware](/stories/revil_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicious COM Object Execution on $Computer$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf2/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf2/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wbemprox_com_object_execution.yml) \| *version*: **1**