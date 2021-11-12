---
title: "Trickbot Named Pipe"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-04-26
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

this search is to detect potential trickbot infection through the create/connected named pipe to the system. This technique is used by trickbot to communicate to its c2 to post or get command during infection.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1804b0a4-a682-11eb-8f68-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```
`sysmon` EventCode IN (17,18) PipeName="\\pipe\\*lacesomepipe" 
| stats  min(_time) as firstTime max(_time) as lastTime count by Computer user_id EventCode PipeName signature Image process_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `trickbot_named_pipe_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and pipename from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. .

#### Required field
* _time
* Computer
* user_id
* EventCode
* PipeName
* signature
* Image
* process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | Possible Trickbot namedpipe created on $Computer$ by $Image$ |




#### Reference

* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/namedpipe/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/namedpipe/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/trickbot_named_pipe.yml) \| *version*: **1**