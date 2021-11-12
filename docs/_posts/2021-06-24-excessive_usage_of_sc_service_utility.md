---
title: "Excessive Usage Of SC Service Utility"
excerpt: "System Services, Service Execution"
categories:
  - Endpoint
last_modified_at: 2021-06-24
toc: true
toc_label: ""
tags:
  - System Services
  - Execution
  - Service Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious excessive usage of sc.exe in a host machine. This technique was seen in several ransomware , xmrig and other malware to create, modify, delete or disable a service may related to security application or to gain privilege escalation.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: cb6b339e-d4c6-11eb-a026-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |

| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |

#### Search

```
`sysmon` EventCode = 1 process_name = "sc.exe" 
|  bucket _time span=15m 
| stats values(process) as process count as numScExe by Computer, _time 
|  eventstats avg(numScExe) as avgScExe, stdev(numScExe) as stdScExe, count as numSlots by Computer 
|  eval upperThreshold=(avgScExe + stdScExe *3) 
|  eval isOutlier=if(avgScExe > 5 and avgScExe >= upperThreshold, 1, 0) 
|  search isOutlier=1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_usage_of_sc_service_utility_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed taskkill.exe may be used.

#### Required field
* _time
* EventCode
* process_name
* process


#### Kill Chain Phase
* Exploitation


#### Known False Positives
excessive execution of sc.exe is quite suspicious since it can modify or execute app in high privilege permission.





#### Reference

* [https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/](https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_usage_of_sc_service_utility.yml) \| *version*: **1**