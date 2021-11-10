---
title: "Regsvr32 Silent Param Dll Loading"
excerpt: "Signed Binary Proxy Execution, Regsvr32"
categories:
  - Endpoint
last_modified_at: 2021-10-04
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Regsvr32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a loading of dll using regsvr32 application with silent parameter and dllinstall execution. This technique was seen in several RAT malware like remcos, njrat and APT&#39;s to load their malicious dll in the compromised machine. This TTP may executed by normal 3rd party application so it is better to pivot the parent process, parent commandline and commandline of the file that execute this regsvr32.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: f421c250-24e7-11ec-bc43-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = regsvr32.exe Processes.process="*/i*" Processes.process="*/s*" by Processes.dest Processes.parent_process Processes.process Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `regsvr32_silent_param_dll_loading_filter`
```

#### Associated Analytic Story
* [Suspicious Regsvr32 Activity](/stories/suspicious_regsvr32_activity)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Other third part application may used this parameter but not so common in base windows environment.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | regsvr32 process with $process$ commandline in $dest$ |




#### Reference

* [https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#](https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#)
* [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/regsvr32_silent_param_dll_loading.yml) \| *version*: **1**