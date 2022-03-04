---
title: "Windows DISM Remove Defender"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-11-17
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Defense Evasion
  - Impair Defenses
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of the Windows Disk Image Utility, `dism.exe`, to remove Windows Defender. Adversaries may use `dism.exe` to disable Defender before completing their objective.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-17
- **Author**: Michael Haag, Splunk
- **ID**: 8567da9e-47f0-11ec-99a9-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=dism.exe (Processes.process="*/online*" AND Processes.process="*/disable-feature*" AND Processes.process="*Windows-Defender*" AND Processes.process="*/remove*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_dism_remove_defender_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_dism_remove_defender_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Some legitimate administrative tools leverage `dism.exe` to manipulate packages and features of the operating system. Filter as needed.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to disable Windows Defender. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon_dism.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon_dism.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_dism_remove_defender.yml) \| *version*: **1**