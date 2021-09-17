---
title: "Wermgr Process Create Executable File"
excerpt: "Obfuscated Files or Information"
categories:
  - Endpoint
last_modified_at: 2021-04-19
toc: true
tags:
  - TTP
  - T1027
  - Obfuscated Files or Information
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

this search is designed to detect potential malicious wermgr.exe process that drops or create executable file. Since wermgr.exe is an application trigger when error encountered in a process, it is really un ussual to this process to drop executable file. This technique is commonly seen in trickbot malware where it injects it code to this process to execute it malicious behavior like downloading other payload

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-19
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion |


#### Search

```
`sysmon` EventCode=11 process_name = "wermgr.exe" TargetFilename = "*.exe" 
| stats  min(_time) as firstTime max(_time) as lastTime count by  Image TargetFilename process_name dest EventCode ProcessId 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wermgr_process_create_executable_file_filter`
```

#### Associated Analytic Story
* [Trickbot](_stories/trickbot)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances of wermgr.exe may be used.

#### Required field
* _time
* Image
* TargetFilename
* process_name
* dest
* EventCode
* ProcessId


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 56.0 | 70 | 80 |



#### Reference

* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log)


_version_: 1