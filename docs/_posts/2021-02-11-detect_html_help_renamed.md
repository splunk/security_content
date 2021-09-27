---
title: "Detect HTML Help Renamed"
excerpt: "Compiled HTML File"
categories:
  - Endpoint
last_modified_at: 2021-02-11
toc: true
tags:
  - TTP
  - T1218.001
  - Compiled HTML File
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a renamed instance of hh.exe (HTML Help) executing a Compiled HTML Help (CHM). This particular technique will load Windows script code from a compiled help file. CHM files may contain nearly any file type embedded, but only execute html/htm. Upon a successful execution, the following script engines may be used for execution - JScript, VBScript, VBScript.Encode, JScript.Encode, JScript.Compact. Analyst may identify vbscript.dll or jscript.dll loading into hh.exe upon execution. The &#34;htm&#34; and &#34;html&#34; file extensions were the only extensions observed to be supported for the execution of Shortcut commands or WSH script code. During investigation, identify script content origination. Validate it is the legitimate version of hh.exe by reviewing the PE metadata. hh.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk
- **ID**: 62fed254-513b-460e-953d-79771493a9f3


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | Compiled HTML File | Defense Evasion |


#### Search

```
`sysmon` EventID=1 OriginalFileName=HH.exe NOT process_name=hh.exe 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_html_help_renamed_filter`
```

#### Associated Analytic Story
* [Suspicious Compiled HTML Activity](/stories/suspicious_compiled_html_activity)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed hh.exe may be used.

#### Required field
* _time
* EventID
* OriginalFileName
* process_name
* Computer
* User
* parent_process_name
* process_path
* CommandLine


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely a renamed instance of hh.exe will be used legitimately, filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The following $process_name$ has been identified as renamed, spawning from $parent_process_name$. |



#### Reference

* [https://attack.mitre.org/techniques/T1218/001/](https://attack.mitre.org/techniques/T1218/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Hh/](https://lolbas-project.github.io/lolbas/Binaries/Hh/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_html_help_renamed.yml) \| *version*: **1**