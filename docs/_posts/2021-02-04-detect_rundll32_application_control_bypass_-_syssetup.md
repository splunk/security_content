---
title: "Detect Rundll32 Application Control Bypass - syssetup"
excerpt: "Signed Binary Proxy Execution, Rundll32"
categories:
  - Endpoint
last_modified_at: 2021-02-04
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Rundll32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies rundll32.exe loading syssetup.dll by calling the LaunchINFSection function on the command line. This particular technique will load script code from a file. Upon a successful execution, the following module loads may occur - clr.dll, jscript.dll and scrobj.dll. During investigation, identify script content origination. Generally, a child process will spawn from rundll32.exe, but that may be bypassed based on script code contents. Rundll32.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64. During investigation, review any network connections and obtain the script content executed. It&#39;s possible other files are on disk.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-04
- **Author**: Michael Haag, Splunk
- **ID**: 71b9bf37-cde1-45fb-b899-1b0aa6fa1183


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_rundll32` Processes.process=*syssetup* by Processes.dest Processes.user Processes.parent_process_name Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_rundll32_application_control_bypass___syssetup_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_rundll32](https://github.com/splunk/security_content/blob/develop/macros/process_rundll32.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_rundll32_application_control_bypass_-_syssetup_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Although unlikely, some legitimate applications may use syssetup.dll, triggering a false positive.

#### Associated Analytic story
* [Suspicious Rundll32 Activity](/stories/suspicious_rundll32_activity)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ loading syssetup.dll by calling the LaunchINFSection function on the command line was identified on endpoint $dest$ by user $user$. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32)
* [https://lolbas-project.github.io/lolbas/Libraries/Syssetup/](https://lolbas-project.github.io/lolbas/Libraries/Syssetup/)
* [https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_rundll32_application_control_bypass_-_syssetup.yml) \| *version*: **2**