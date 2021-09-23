---
title: "Suspicious DLLHost no Command Line Arguments"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-02-23
toc: true
tags:
  - TTP
  - T1055
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---



[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies DLLHost.exe with no command line arguments. It is unusual for DLLHost.exe to execute with no command line arguments present. This particular behavior is common with malicious software, including Cobalt Strike. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. DLLHost.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **ID**: ff61e98c-0337-4593-a78f-72a676c56f26
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-23
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |


#### Search

```
`sysmon` EventID=1 (process_name=dllhost.exe OR OriginalFileName=dllhost.exe) 
| regex CommandLine="(dllhost\.exe.{0,4}$)" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, User, ParentImage,ParentCommandLine, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_dllhost_no_command_line_arguments_filter`
```

#### Associated Analytic Story
* [Cobalt Strike](/stories/cobalt_strike)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* EventID
* process_name
* OriginalFileName
* CommandLine
* dest
* User
* ParentImage
* ParentCommandLine
* process_path


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Limited false positives may be present in small environments. Tuning may be required based on parent process.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Suspicious dllhost.exe process with no command line arguments executed on $dest$ by $user$ |



#### Reference

* [https://raw.githubusercontent.com/threatexpress/malleable-c2/c3385e481159a759f79b8acfe11acf240893b830/jquery-c2.4.2.profile](https://raw.githubusercontent.com/threatexpress/malleable-c2/c3385e481159a759f79b8acfe11acf240893b830/jquery-c2.4.2.profile)
* [https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/](https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_dllhost_no_command_line_arguments.yml) \| *version*: **1**