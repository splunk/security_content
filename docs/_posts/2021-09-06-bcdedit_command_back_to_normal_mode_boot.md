---
title: "Bcdedit Command Back To Normal Mode Boot"
excerpt: "Inhibit System Recovery"
categories:
  - Endpoint
last_modified_at: 2021-09-06
toc: true
toc_label: ""
tags:
  - Inhibit System Recovery
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious bcdedit commandline to configure the host from safe mode back to normal boot configuration. This technique was seen in blackMatter ransomware where it force the compromised host to boot in safe mode to continue its encryption and bring back to normal boot using bcdedit deletevalue command. This TTP can be a good alert for host that booted from safe mode forcefully since it need to modify the boot configuration to bring it back to normal.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: dc7a8004-0f18-11ec-8c54-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = bcdedit.exe Processes.process="*/deletevalue*" Processes.process="*{current}*"  Processes.process="*safeboot*" by Processes.process_name Processes.process Processes.parent_process_name Processes.dest Processes.user 
|`drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `bcdedit_command_back_to_normal_mode_boot_filter`
```

#### Associated Analytic Story
* [BlackMatter Ransomware](/stories/blackmatter_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.parent_process
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | bcdedit process with commandline $process$ to bring back to normal boot configuration the $dest$ |




#### Reference

* [https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/](https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/bcdedit_command_back_to_normal_mode_boot.yml) \| *version*: **1**