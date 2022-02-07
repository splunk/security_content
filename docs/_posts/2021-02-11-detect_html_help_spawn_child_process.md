---
title: "Detect HTML Help Spawn Child Process"
excerpt: "Signed Binary Proxy Execution, Compiled HTML File"
categories:
  - Endpoint
last_modified_at: 2021-02-11
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Compiled HTML File
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies hh.exe (HTML Help) execution of a Compiled HTML Help (CHM) that spawns a child process. This particular technique will load Windows script code from a compiled help file. CHM files may contain nearly any file type embedded, but only execute html/htm. Upon a successful execution, the following script engines may be used for execution - JScript, VBScript, VBScript.Encode, JScript.Encode, JScript.Compact. Analyst may identify vbscript.dll or jscript.dll loading into hh.exe upon execution. The &#34;htm&#34; and &#34;html&#34; file extensions were the only extensions observed to be supported for the execution of Shortcut commands or WSH script code. During investigation, identify script content origination. Review child process events and investigate further. hh.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk
- **ID**: 723716de-ee55-4cd4-9759-c44e7e55ba4b


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | Compiled HTML File | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=hh.exe by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_html_help_spawn_child_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_html_help_spawn_child_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Although unlikely, some legitimate applications (ex. web browsers) may spawn a child process. Filter as needed.

#### Associated Analytic story
* [Suspicious Compiled HTML Activity](/stories/suspicious_compiled_html_activity)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ spawning a child process, typically not normal behavior. |




#### Reference

* [https://attack.mitre.org/techniques/T1218/001/](https://attack.mitre.org/techniques/T1218/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Hh/](https://lolbas-project.github.io/lolbas/Binaries/Hh/)
* [https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7)
* [https://cyberforensicator.com/2019/01/20/silence-dissecting-malicious-chm-files-and-performing-forensic-analysis/](https://cyberforensicator.com/2019/01/20/silence-dissecting-malicious-chm-files-and-performing-forensic-analysis/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_html_help_spawn_child_process.yml) \| *version*: **1**