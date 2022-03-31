---
title: "Rundll32 Control RunDLL Hunt"
excerpt: "Signed Binary Proxy Execution
, Rundll32
"
categories:
  - Endpoint
last_modified_at: 2021-09-08
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Rundll32
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-40444
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting detection identifies rundll32.exe with `control_rundll` within the command-line, loading a .cpl or another file type. Developed in relation to CVE-2021-40444. Rundll32.exe can also be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions Control_RunDLL and Control_RunDLLAsUser. Double-clicking a .cpl file also causes rundll32.exe to execute. \ This is written to be a bit more broad by not including .cpl. \ During triage, review parallel processes to identify any further suspicious behavior.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-08
- **Author**: Michael Haag, Splunk
- **ID**: c8e7ced0-10c5-11ec-8b03-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_rundll32` Processes.process=*Control_RunDLL*  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rundll32_control_rundll_hunt_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_rundll32](https://github.com/splunk/security_content/blob/develop/macros/process_rundll32.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `rundll32_control_rundll_hunt_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
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
This is a hunting detection, meant to provide a understanding of how voluminous control_rundll is within the environment.

#### Associated Analytic story
* [Suspicious Rundll32 Activity](/stories/suspicious_rundll32_activity)
* [Microsoft MSHTML Remote Code Execution CVE-2021-40444](/stories/microsoft_mshtml_remote_code_execution_cve-2021-40444)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to load a suspicious file from disk. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-40444](https://nvd.nist.gov/vuln/detail/CVE-2021-40444) | Microsoft MSHTML Remote Code Execution Vulnerability | 6.8 |



#### Reference

* [https://strontic.github.io/xcyclopedia/library/rundll32.exe-111474C61232202B5B588D2B512CBB25.html](https://strontic.github.io/xcyclopedia/library/rundll32.exe-111474C61232202B5B588D2B512CBB25.html)
* [https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/](https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/)
* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.002/T1218.002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.002/T1218.002.yaml)
* [https://redcanary.com/blog/intelligence-insights-december-2021/](https://redcanary.com/blog/intelligence-insights-december-2021/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rundll32_control_rundll_hunt.yml) \| *version*: **1**