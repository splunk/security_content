---
title: "Office Document Executing Macro Code"
excerpt: "Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-14
toc: true
tags:
  - TTP
  - T1566.001
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this detection was designed to identifies suspicious office documents that using macro code. Macro code is known to be one of the prevalent weaponization or attack vector of threat actor. This malicious macro code is embed to a office document as an attachment that may execute malicious payload, download malware payload or other malware component. It is really good practice to disable macro by default to avoid automatically execute macro code while opening or closing a office document files.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: b12c89bc-9d06-11eb-a592-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```
`sysmon` EventCode=7 process_name IN ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") ImageLoaded IN ("*\\VBE7INTL.DLL","*\\VBE7.DLL", "*\\VBEUI.DLL") 
| stats min(_time) as firstTime max(_time) as lastTime values(ImageLoaded) as AllImageLoaded count by Computer EventCode Image process_name ProcessId ProcessGuid 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `office_document_executing_macro_code_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Trickbot](/stories/trickbot)
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and ImageLoaded (Like sysmon EventCode 7) from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Also be sure to include those monitored dll to your own sysmon config.

#### Required field
* ImageLoaded
* AllImageLoaded
* Computer
* EventCode
* Image
* process_name
* ProcessId
* ProcessGuid
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Normal Office Document macro use for automation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Office document executing a macro on $dest$ |



#### Reference

* [https://www.joesandbox.com/analysis/386500/0/html](https://www.joesandbox.com/analysis/386500/0/html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_document_executing_macro_code.yml) \| *version*: **1**