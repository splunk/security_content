---
title: "Suspicious Process DNS Query Known Abuse Web Services"
excerpt: "Visual Basic, Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2022-01-18
toc: true
toc_label: ""
tags:
  - Visual Basic
  - Execution
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic detects a suspicious process making a DNS query via known, abused text-paste web services, VoIP, instant messaging, and digital distribution platforms used to download external files. This technique is abused by adversaries, malware actors, and red teams to download a malicious file on the target host. This is a good TTP indicator for possible initial access techniques. A user will experience false positives if the following instant messaging is allowed or common applications like telegram or discord are allowed in the corporate network.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-18
- **Author**: Teoderick Contreras, Splunk
- **ID**: 3cf0dc36-484d-11ec-a6bc-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Visual Basic | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```
`sysmon` EventCode=22 QueryName IN ("*pastebin*", "*discord*", "*telegram*", "*t.me*") process_name IN ("cmd.exe", "*powershell*", "pwsh.exe", "wscript.exe", "cscript.exe") 
| stats count min(_time) as firstTime max(_time) as lastTime by Image QueryName QueryStatus process_name QueryResults Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_process_dns_query_known_abuse_web_services_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `suspicious_process_dns_query_known_abuse_web_services_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* QueryName
* QueryStatus
* process_name
* QueryResults
* Computer


#### How To Implement
This detection relies on sysmon logs with the Event ID 22, DNS Query. We suggest you run this detection at least once a day over the last 14 days.

#### Known False Positives
Noise and false positive can be seen if the following instant messaging is allowed to use within corporate network. In this case, a filter is needed.

#### Associated Analytic story
* [Remcos](/stories/remcos)
* [WhisperGate](/stories/whispergate)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | suspicious process $process_name$ has a dns query in $QueryName$ on $Computer$ |




#### Reference

* [https://urlhaus.abuse.ch/url/1798923/](https://urlhaus.abuse.ch/url/1798923/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_pastebin_download/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_pastebin_download/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_process_dns_query_known_abuse_web_services.yml) \| *version*: **2**