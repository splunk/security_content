---
title: "Rundll32 CreateRemoteThread In Browser"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-07-26
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies the suspicious Remote Thread execution of rundll32.exe process to &#34;firefox.exe&#34; and &#34;chrome.exe&#34; browser. This technique was seen in IcedID malware where it hooks the browser to parse banking information as user used the targetted browser process.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: f8a22586-ee2d-11eb-a193-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```
`sysmon` EventCode=8 SourceImage = "*\\rundll32.exe" TargetImage IN ("*\\firefox.exe", "*\\chrome.exe", "*\\iexplore.exe","*\\microsoftedgecp.exe") 
| stats count min(_time) as firstTime max(_time) as lastTime by SourceImage TargetImage TargetProcessId SourceProcessId StartAddress EventCode Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rundll32_createremotethread_in_browser_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the SourceImage, TargetImage, and EventCode executions from your endpoints related to create remote thread or injecting codes. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* SourceImage
* TargetImage
* TargetProcessId
* SourceProcessId
* StartAddress
* EventCode
* Computer


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | rundl32 process $SourceImage$ create a remote thread to browser process $TargetImage$ in host $Computer$ |




#### Reference

* [https://www.joesandbox.com/analysis/380662/0/html](https://www.joesandbox.com/analysis/380662/0/html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rundll32_createremotethread_in_browser.yml) \| *version*: **1**