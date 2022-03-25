---
title: "Loading Of Dynwrapx Module"
excerpt: "Process Injection
, Dynamic-link Library Injection
"
categories:
  - Endpoint
last_modified_at: 2021-11-18
toc: true
toc_label: ""
tags:
  - Process Injection
  - Dynamic-link Library Injection
  - Defense Evasion
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

DynamicWrapperX is an ActiveX component that can be used in a script to call Windows API functions, but it requires the dynwrapx.dll to be installed and registered. With that, registering or loading dynwrapx.dll to a host is highly suspicious. In most instances when it is used maliciously, the best way to triage is to review parallel processes and pivot on the process_guid. Review the registry for any suspicious modifications meant to load dynwrapx.dll. Identify any suspicious module loads of dynwrapx.dll. This detection will return and identify the processes that invoke vbs/wscript/cscript.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-11-18
- **Author**: Teoderick Contreras, Splunk
- **ID**: eac5e8ba-4857-11ec-9371-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Defense Evasion, Privilege Escalation |

#### Search

```
`sysmon` EventCode=7 (ImageLoaded = "*\\dynwrapx.dll" OR OriginalFileName = "dynwrapx.dll" OR  Product = "DynamicWrapperX") 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded OriginalFileName Product process_name Computer EventCode Signed ProcessId 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `loading_of_dynwrapx_module_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `loading_of_dynwrapx_module_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* ImageLoaded
* OriginalFileName
* Product
* process_name
* Computer
* EventCode
* Signed
* ProcessId


#### How To Implement
To successfully implement this search you need to be ingesting information on processes that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited, however it is possible to filter by Processes.process_name and specific processes (ex. wscript.exe). Filter as needed. This may need modification based on EDR telemetry and how it brings in registry data. For example, removal of (Default).

#### Associated Analytic story
* [Remcos](/stories/remcos)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | dynwrapx.dll loaded by process $process_name$ on $Computer$ |




#### Reference

* [https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/](https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/)
* [https://www.script-coding.com/dynwrapx_eng.html](https://www.script-coding.com/dynwrapx_eng.html)
* [https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
* [https://tria.ge/210929-ap75vsddan](https://tria.ge/210929-ap75vsddan)
* [https://www.virustotal.com/gui/file/cb77b93150cb0f7fe65ce8a7e2a5781e727419451355a7736db84109fa215a89](https://www.virustotal.com/gui/file/cb77b93150cb0f7fe65ce8a7e2a5781e727419451355a7736db84109fa215a89)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_dynwrapx/sysmon_dynwraper.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_dynwrapx/sysmon_dynwraper.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/loading_of_dynwrapx_module.yml) \| *version*: **1**