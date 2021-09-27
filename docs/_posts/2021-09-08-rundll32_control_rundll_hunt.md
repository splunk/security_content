---
title: "Rundll32 Control RunDLL Hunt"
excerpt: "Rundll32"
categories:
  - Endpoint
last_modified_at: 2021-09-08
toc: true
tags:
  - Hunting
  - T1218.011
  - Rundll32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting detection identifies rundll32.exe with `control_rundll` within the command-line, loading a .cpl or another file type. Developed in relation to CVE-2021-40444. Rundll32.exe can also be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions Control_RunDLL and Control_RunDLLAsUser. Double-clicking a .cpl file also causes rundll32.exe to execute. \ This is written to be a bit more broad by not including .cpl. \ During triage, review parallel processes to identify any further suspicious behavior.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-08
- **Author**: Michael Haag, Splunk
- **ID**: c8e7ced0-10c5-11ec-8b03-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=rundll32.exe OR Processes.original_file_name=RUNDLL32.EXE) Processes.process=*Control_RunDLL*  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rundll32_control_rundll_hunt_filter`
```

#### Associated Analytic Story
* [Suspicious Rundll32 Activity](/stories/suspicious_rundll32_activity)
* [Microsoft MSHTML Remote Code Execution CVE-2021-40444](/stories/microsoft_mshtml_remote_code_execution_cve-2021-40444)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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


#### Kill Chain Phase
* Exploitation


#### Known False Positives
This is a hunting detection, meant to provide a understanding of how voluminous control_rundll is within the environment.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to load a suspicious file from disk. |



#### Reference

* [https://strontic.github.io/xcyclopedia/library/rundll32.exe-111474C61232202B5B588D2B512CBB25.html](https://strontic.github.io/xcyclopedia/library/rundll32.exe-111474C61232202B5B588D2B512CBB25.html)
* [https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/](https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/)
* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.002/T1218.002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.002/T1218.002.yaml)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rundll32_control_rundll_hunt.yml) \| *version*: **1**