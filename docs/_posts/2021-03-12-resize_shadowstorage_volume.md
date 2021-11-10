---
title: "Resize ShadowStorage volume"
excerpt: "Inhibit System Recovery"
categories:
  - Endpoint
last_modified_at: 2021-03-12
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

The following analytics identifies the resizing of shadowstorage by ransomware malware to avoid the shadow volumes being made again. this technique is an alternative by ransomware attacker than deleting the shadowstorage which is known alert in defensive team. one example of ransomware that use this technique is CLOP ransomware where it drops a .bat file that will resize the shadowstorage to minimum size as much as possible

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-12
- **Author**: Teoderick Contreras
- **ID**: bc760ca6-8336-11eb-bcbb-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as cmdline values(Processes.parent_process_name) as parent_process values(Processes.process_name) as process_name min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name = "cmd.exe" OR Processes.parent_process_name = "powershell.exe" OR Processes.parent_process_name = "powershell_ise.exe" OR Processes.parent_process_name =  "wmic.exe" Processes.process_name = "vssadmin.exe" Processes.process="*resize*" Processes.process="*shadowstorage*" Processes.process="*/maxsize*" by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.dest Processes.user Processes.process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `resize_shadowstorage_volume_filter`
```

#### Associated Analytic Story
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* Processes.process
* Process.parent_process_name
* _time
* Processes.process_name
* Processes.parent_process
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
network admin can resize the shadowstorage for valid purposes.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | A process $parent_process_name$ attempt to resize shadow copy with commandline $process$ in host $dest$ |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/resize_shadowstorage_volume.yml) \| *version*: **1**