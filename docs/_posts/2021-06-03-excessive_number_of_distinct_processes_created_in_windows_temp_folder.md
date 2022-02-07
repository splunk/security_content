---
title: "Excessive number of distinct processes created in Windows Temp folder"
excerpt: "Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2021-06-03
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious series of process executions.  We have observed that post exploit framework tools like Koadic and Meterpreter will launch an excessive number of processes with distinct file paths from Windows\Temp to execute actions on objective.  This behavior is extremely anomalous compared to typical application behaviors that use Windows\Temp.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-03
- **Author**: Michael Hart, Splunk
- **ID**: 23587b6a-c479-11eb-b671-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process distinct_count(Processes.process) as distinct_process_count  min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process = "*\\Windows\\Temp\\*" by Processes.dest Processes.user  _time span=20m 
| where distinct_process_count > 37 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_number_of_distinct_processes_created_in_windows_temp_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `excessive_number_of_distinct_processes_created_in_windows_temp_folder_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the full process path in the process field of CIM&#39;s Process data model. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed sc.exe may be used.

#### Known False Positives
Many benign applications will create processes from executables in Windows\Temp, although unlikely to exceed the given threshold.  Filter as needed.

#### Associated Analytic story
* [Meterpreter](/stories/meterpreter)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | Multiple processes were executed out of windows\temp within a short amount of time on $dest$. |




#### Reference

* [https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/meterpreter/windows_temp_processes/logExcessiveWindowsTemp.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/meterpreter/windows_temp_processes/logExcessiveWindowsTemp.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_number_of_distinct_processes_created_in_windows_temp_folder.yml) \| *version*: **1**