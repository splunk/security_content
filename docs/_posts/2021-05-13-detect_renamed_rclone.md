---
title: "Detect Renamed RClone"
excerpt: "Automated Exfiltration"
categories:
  - Endpoint
last_modified_at: 2021-05-13
toc: true
tags:
  - TTP
  - T1020
  - Automated Exfiltration
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exfiltration
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the usage of `rclone.exe`, renamed, being used to exfiltrate data to a remote destination. RClone has been used by multiple ransomware groups to exfiltrate data. In many instances, it will be downloaded from the legitimate site and executed accordingly. During triage, isolate the endpoint and begin to review parallel processes for additional behavior. At this stage, the adversary may have staged data to be exfiltrated.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-05-13
- **Author**: Michael Haag, Splunk
- **ID**: 6dca1124-b3ec-11eb-9328-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Exfiltration |


#### Search

```
`sysmon` EventID=1 OriginalFileName=rclone.exe NOT process_name=rclone.exe 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_rclone_filter`
```

#### Associated Analytic Story
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* OriginalFileName
* process_name
* process_path
* CommandLine
* dest


#### Kill Chain Phase
* Exfiltration


#### Known False Positives
False positives should be limited as this analytic identifies renamed instances of `rclone.exe`. Filter as needed if there is a legitimate business use case.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | The following $process_name$ has been identified as renamed, spawning from $parent_process_name$ on $dest$ by $user$. |



#### Reference

* [https://redcanary.com/blog/rclone-mega-extortion/](https://redcanary.com/blog/rclone-mega-extortion/)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)
* [https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_renamed_rclone.yml) \| *version*: **1**