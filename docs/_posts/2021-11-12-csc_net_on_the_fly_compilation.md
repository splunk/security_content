---
title: "CSC Net On The Fly Compilation"
excerpt: "Compile After Delivery
, Obfuscated Files or Information
"
categories:
  - Endpoint
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - Compile After Delivery
  - Obfuscated Files or Information
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

this analytic is to detect a suspicious compile before delivery approach of .net compiler csc.exe. This technique was seen in several adversaries, malware and even in red teams to take advantage the csc.exe .net compiler tool to compile on the fly a malicious .net code to evade detection from security product. This is a good hunting query to check further the file or process created after this event and check the file path that passed to csc.exe which is the .net code. Aside from that, powershell is capable of using this compiler in executing .net code in a powershell script so filter on that case is needed.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-11-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: ea73128a-43ab-11ec-9753-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1027.004](https://attack.mitre.org/techniques/T1027/004/) | Compile After Delivery | Defense Evasion |

| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_csc` Processes.process = "*/noconfig*" Processes.process = "*/fullpaths*" Processes.process = "*@*" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `csc_net_on_the_fly_compilation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_csc](https://github.com/splunk/security_content/blob/develop/macros/process_csc.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `csc_net_on_the_fly_compilation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
A network operator or systems administrator may utilize an automated powershell script taht execute .net code that may generate false positive. filter is needed.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | csc.exe with commandline $process$ to compile .net code on $dest$ by $user$ |




#### Reference

* [https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/](https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/)
* [https://tccontre.blogspot.com/2019/06/maicious-macro-that-compile-c-code-as.html](https://tccontre.blogspot.com/2019/06/maicious-macro-that-compile-c-code-as.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/csc_net_on_the_fly_compilation.yml) \| *version*: **1**