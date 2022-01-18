---
title: "Services Escalate Exe"
excerpt: "Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2021-05-18
toc: true
toc_label: ""
tags:
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of `svc-exe` with Cobalt Strike. The behavior typically follows after an adversary has already gained initial access and is escalating privileges. Using `svc-exe`, a randomly named binary will be downloaded from the remote Teamserver and placed on disk within `C:\Windows\400619a.exe`. Following, the binary will be added to the registry under key `HKLM\System\CurrentControlSet\Services\400619a\` with multiple keys and values added to look like a legitimate service. Upon loading, `services.exe` will spawn the randomly named binary from `\\127.0.0.1\ADMIN$\400619a.exe`. The process lineage is completed with `400619a.exe` spawning rundll32.exe, which is the default `spawnto_` value for Cobalt Strike. The `spawnto_` value is arbitrary and may be any process on disk (typically system32/syswow64 binary). The `spawnto_` process will also contain a network connection. During triage, review parallel procesess and identify any additional file modifications.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-18
- **Author**: Michael Haag, Splunk
- **ID**: c448488c-b7ec-11eb-8253-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=services.exe Processes.process_path=*admin$* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `services_escalate_exe_filter`
```

#### Associated Analytic Story
* [Cobalt Strike](/stories/cobalt_strike)


#### How To Implement
To successfully implement this search, you will need to ensure that DNS data is populating the Network_Resolution data model.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation
* Privilege Escalation


#### Known False Positives
False positives should be limited as `services.exe` should never spawn a process from `ADMIN$`. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 76.0 | 80 | 95 | A service process $parent_process_name$ with process path $process_path$ in host $dest$ |




#### Reference

* [https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
* [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)
* [https://www.cobaltstrike.com/help-beacon](https://www.cobaltstrike.com/help-beacon)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/services_escalate_exe.yml) \| *version*: **1**