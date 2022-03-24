---
title: "Suspicious Process File Path"
excerpt: "Create or Modify System Process
"
categories:
  - Endpoint
last_modified_at: 2021-05-05
toc: true
toc_label: ""
tags:
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic will detect a suspicious process running in a file path where a process is not commonly seen and is most commonly used by malicious software. This behavior has been used by adversaries where they drop and run an exe in a path that is accessible without admin privileges.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-05-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9be25988-ad82-11eb-a14f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_path = "*\\windows\\fonts\\*" OR Processes.process_path = "*\\windows\\temp\\*" OR Processes.process_path = "*\\users\\public\\*" OR Processes.process_path = "*\\windows\\debug\\*" OR Processes.process_path.file_path = "*\\Users\\Administrator\\Music\\*" OR Processes.process_path.file_path = "*\\Windows\\servicing\\*" OR Processes.process_path.file_path = "*\\Users\\Default\\*" OR Processes.process_path.file_path = "*Recycle.bin*" OR Processes.process_path = "*\\Windows\\Media\\*" OR Processes.process_path = "\\Windows\\repair\\*" OR Processes.process_path = "*\\temp\\*" OR Processes.process_path = "*\\PerfLogs\\*" by Processes.parent_process_name Processes.parent_process Processes.process_path Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_process_file_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `suspicious_process_file_path_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_path
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Administrators may allow execution of specific binaries in non-standard paths. Filter as needed.

#### Associated Analytic story
* [XMRig](/stories/xmrig)
* [Remcos](/stories/remcos)
* [WhisperGate](/stories/whispergate)
* [Hermetic Wiper](/stories/hermetic_wiper)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicioues process $Processes.process_path.file_path$ running from suspicious location |




#### Reference

* [https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/](https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_process_file_path.yml) \| *version*: **1**