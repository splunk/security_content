---
title: "Windows Powershell Connect to Internet With Hidden Window"
excerpt: "Automated Exfiltration"
categories:
  - Endpoint
last_modified_at: 2022-02-11
toc: true
toc_label: ""
tags:
  - Automated Exfiltration
  - Exfiltration
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic identifies PowerShell commands utilizing the WindowStyle parameter to hide the window on the compromised endpoint. This combination of command-line options is suspicious because it is overriding the default PowerShell execution policy, attempts to hide its activity from the user, and connects to the Internet. Removed in this version of the query is New-Object. The analytic identifies all variations of WindowStyle, as PowerShell allows the ability to shorten the parameter. For example w, win, windowsty and so forth. In addition, through our research it was identified that PowerShell will interpret different command switch types beyond the hyphen. We have added endash, emdash, horizontal bar, and forward slash.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-11
- **Author**: Jose Hernandez, David Dorsey, Michael Haag Splunk
- **ID**: 477e068e-8b6d-11ec-b6c1-81af21670352


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Exfiltration |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL 
| where process_name="pwsh.exe" OR process_name="pwsh.exe" OR process_name="sqlps.exe" OR process_name="sqltoolsps.exe" OR process_name="powershell.exe" OR process_name="powershell_ise.exe" 
| where match_regex(cmd_line, /(?i)[\\-
|\\/
|\u2013\
|\u2014
|\u2015]w(in*d*o*w*s*t*y*l*e*)*\\s+[^-]/)=true 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_powershell_connect_to_internet_with_hidden_window_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process
* cmd_line


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Known False Positives
Legitimate process can have this combination of command-line options, but it&#39;s not common.

#### Associated Analytic story
* [Malicious PowerShell](/stories/malicious_powershell)
* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns)
* [HAFNIUM Group](/stories/hafnium_group)
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### Kill Chain Phase
* Exfiltration



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | PowerShell processes $process$ started with parameters to modify the execution policy of the run, run in a hidden window, and connect to the Internet on host $dest$ executed by user $user$. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://regexr.com/663rr](https://regexr.com/663rr)
* [https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1](https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1)
* [https://ss64.com/ps/powershell.html](https://ss64.com/ps/powershell.html)
* [https://twitter.com/M_haggis/status/1440758396534214658?s=20](https://twitter.com/M_haggis/status/1440758396534214658?s=20)
* [https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/](https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/hidden_powershell/hidden_windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/hidden_powershell/hidden_windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_powershell_connect_to_internet_with_hidden_window.yml) \| *version*: **1**