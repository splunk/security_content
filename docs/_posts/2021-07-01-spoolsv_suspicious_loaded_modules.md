---
title: "Spoolsv Suspicious Loaded Modules"
excerpt: "Print Processors"
categories:
  - Endpoint
last_modified_at: 2021-07-01
toc: true
tags:
  - TTP
  - T1547.012
  - Print Processors
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

This search is to detect suspicious loading of dll in specific path relative to printnightmare exploitation. In this search we try to detect the loaded modules made by spoolsv.exe after the exploitation.

- **ID**: a5e451f8-da81-11eb-b245-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-01
- **Author**: Mauricio Velazco, Michael Haag, Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1547.012](https://attack.mitre.org/techniques/T1547/012/) | Print Processors | Persistence, Privilege Escalation |


#### Search

```
`sysmon` EventCode=7 Image ="*\\spoolsv.exe" ImageLoaded="*\\Windows\\System32\\spool\\drivers\\x64\\*" ImageLoaded = "*.dll" 
| stats dc(ImageLoaded) as countImgloaded values(ImageLoaded) as ImgLoaded count min(_time) as firstTime max(_time) as lastTime by Image Computer process_id EventCode 
| where countImgloaded >= 3 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `spoolsv_suspicious_loaded_modules_filter`
```

#### Associated Analytic Story
* [PrintNightmare CVE-2021-34527](/stories/printnightmare_cve-2021-34527)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Image
* Computer
* EventCode
* ImageLoaded


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 72.0 | 80 | 90 |



#### Reference

* [https://raw.githubusercontent.com/hieuttmmo/sigma/dceb13fe3f1821b119ae495b41e24438bd97e3d0/rules/windows/image_load/sysmon_cve_2021_1675_print_nightmare.yml](https://raw.githubusercontent.com/hieuttmmo/sigma/dceb13fe3f1821b119ae495b41e24438bd97e3d0/rules/windows/image_load/sysmon_cve_2021_1675_print_nightmare.yml)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/spoolsv_suspicious_loaded_modules.yml) \| *version*: **1**