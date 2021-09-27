---
title: "Wbemprox COM Object Execution"
excerpt: "CMSTP"
categories:
  - Endpoint
last_modified_at: 2021-06-02
toc: true
tags:
  - TTP
  - T1218.003
  - CMSTP
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search is designed to detect potential malicious process loading COM object to wbemprox.dll,

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9d911ce0-c3be-11eb-b177-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.003](https://attack.mitre.org/techniques/T1218/003/) | CMSTP | Defense Evasion |


#### Search

```
`sysmon` EventCode=7  ImageLoaded IN ("*\\fastprox.dll", "*\\wbemprox.dll", "*\\wbemcomn.dll") NOT (process_name IN ("wmiprvse.exe", "WmiApSrv.exe", "unsecapp.exe")) NOT(Image IN("*\\windows\\*","*\\program files*", "*\\wbem\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded process_name Computer EventCode Signed ProcessId Hashes IMPHASH 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wbemprox_com_object_execution_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)
* [Revil Ransomware](/stories/revil_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

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


#### Kill Chain Phase
* Exploitation


#### Known False Positives
legitimate process that are not in the exception list may trigger this event.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicious COM Object Execution on $Computer$ |



#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf2/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf2/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wbemprox_com_object_execution.yml) \| *version*: **1**