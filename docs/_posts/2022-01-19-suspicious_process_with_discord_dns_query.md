---
title: "Suspicious Process With Discord DNS Query"
excerpt: "Visual Basic, Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2022-01-19
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

This analytic identifies a process making a DNS query to Discord, a well known instant messaging and digital distribution platform. Discord can be abused by adversaries, as seen in the WhisperGate campaign, to host and download malicious. external files. A process resolving a Discord DNS name could be an indicator of malware trying to download files from Discord for further execution.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4d4332ae-792c-11ec-89c1-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Visual Basic | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```
`sysmon` EventCode=22 QueryName IN ("*discord*") process_path != "*\\AppData\\Local\\Discord\\*" AND process_path != "*\\Program Files*" AND process_name != "discord.exe" 
| stats count min(_time) as firstTime max(_time) as lastTime by Image QueryName QueryStatus process_name QueryResults Computer process_path 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_process_with_discord_dns_query_filter`
```

#### Associated Analytic Story
* [WhisperGate](/stories/whispergate)


#### How To Implement
his detection relies on sysmon logs with the Event ID 22, DNS Query.

#### Required field
* _time
* Image
* QueryName
* QueryStatus
* process_name
* QueryResults
* Computer
* process_path


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Noise and false positive can be seen if the following instant messaging is allowed to use within corporate network. In this case, a filter is needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | suspicious process $process_name$ has a dns query in $QueryName$ on $Computer$ |




#### Reference

* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
* [https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3](https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/discord_dnsquery/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/discord_dnsquery/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_process_with_discord_dns_query.yml) \| *version*: **1**