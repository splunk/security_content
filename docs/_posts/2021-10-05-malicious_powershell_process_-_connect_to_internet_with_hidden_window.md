---
title: "Malicious PowerShell Process - Connect To Internet With Hidden Window"
excerpt: "PowerShell, Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - PowerShell
  - Execution
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic identifies PowerShell commands utilizing the WindowStyle parameter to hide the window on the compromised endpoint. This combination of command-line options is suspicious because it is overriding the default PowerShell execution policy, attempts to hide its activity from the user, and connects to the Internet. Removed in this version of the query is New-Object. The analytic identifies all variations of WindowStyle, as PowerShell allows the ability to shorten the parameter. For example w, win, windowsty and so forth. In addition, through our research it was identified that PowerShell will interpret different command switch types beyond the hyphen. We have added endash, emdash, horizontal bar, and forward slash.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-05
- **Author**: David Dorsey, Michael Haag Splunk
- **ID**: ee18ed37-0802-4268-9435-b3b91aaa18db


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_powershell` by Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.original_file_name Processes.dest Processes.process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| where match(process,"(?i)[\-
|\/
|–
|—
|―]w(in*d*o*w*s*t*y*l*e*)*\s+[^-]") 
| `malicious_powershell_process___connect_to_internet_with_hidden_window_filter`
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)
* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process
* Processes.process_name
* Processes.user
* Processes.parent_process_name
* Processes.dest


#### Kill Chain Phase
* Command and Control
* Actions on Objectives


#### Known False Positives
Legitimate process can have this combination of command-line options, but it&#39;s not common.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | PowerShell processes $process$ started with parameters to modify the execution policy of the run, run in a hidden window, and connect to the Internet on host $dest$ executed by user $user$. |




#### Reference

* [https://regexr.com/663rr](https://regexr.com/663rr)
* [https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1](https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1)
* [https://ss64.com/ps/powershell.html](https://ss64.com/ps/powershell.html)
* [https://twitter.com/M_haggis/status/1440758396534214658?s=20](https://twitter.com/M_haggis/status/1440758396534214658?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/hidden_powershell/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/hidden_powershell/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_powershell_process_-_connect_to_internet_with_hidden_window.yml) \| *version*: **7**