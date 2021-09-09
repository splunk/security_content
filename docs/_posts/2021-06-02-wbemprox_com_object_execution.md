---
title: "Wbemprox COM Object Execution"
last_modified_at: 2021-06-02
categories:
  - Endpoint
tags:
  - T1218.003
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

this search is designed to detect potential malicious process loading COM object to wbemprox.dll,

#### Search

```

`sysmon` EventCode=7  ImageLoaded IN ("*\\fastprox.dll", "*\\wbemprox.dll", "*\\wbemcomn.dll") NOT (process_name IN ("wmiprvse.exe", "WmiApSrv.exe", "unsecapp.exe")) NOT(Image IN("*\\windows\\*","*\\program files
*", "*\\wbem\\*"))
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded process_name Computer EventCode Signed ProcessId Hashes IMPHASH
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `wbemprox_com_object_execution_filter`

```

#### Associated Analytic Story

* Ransomware

* Revil Ransomware




#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysm
on TA.

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



#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.003 | CMSTP | Defense Evasion |


#### Kill Chain Phase

* Exploitation


#### Known False Positives
legitimate process that are not in the exception list may trigger this event.

#### Reference


* https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/

* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/



#### Test Dataset

* https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf2/windows-sysmon.log


_version_: 1
