---
title: "Randomly Generated Windows Service Name"
excerpt: "Create or Modify System Process
, Windows Service
"
categories:
  - Endpoint
last_modified_at: 2021-11-29
toc: true
toc_label: ""
tags:
  - Create or Modify System Process
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic leverages Event ID 7045, `A new service was installed in the system`, to identify the installation of a Windows Service with a suspicious, high entropy, Service Name. To achieve this, this analytic also leverages the `ut_shannon` function from the URL ToolBox Splunk application. Red teams and adversaries alike may abuse the Service Control Manager to create and start a remote Windows Service and obtain remote code execution. To achieve this goal, some tools like Metasploit, Cobalt Strike and Impacket, typically create a Windows Service with a random service name on the victim host. This hunting analytic may help defenders identify Windows Services installed as part of a lateral movement attack. The entropy threshold `ut_shannon > 3` should be customized by users. The Service_File_Name field can be used to determine if the Windows Service has malicious intent or not.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-11-29
- **Author**: Mauricio Velazco, Splunk
- **ID**: 2032a95a-5165-11ec-a2c3-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

#### Search

```
 `wineventlog_system` EventCode=7045 
| lookup ut_shannon_lookup word as Service_Name 
| where ut_shannon > 3 
| table EventCode ComputerName Service_Name ut_shannon Service_Start_Type Service_Type Service_File_Name 
| `randomly_generated_windows_service_name_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)

Note that `randomly_generated_windows_service_name_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* ComputerName
* Service_File_Name
* Service_Type
* Service_Name
* Service_Start_Type


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints. The Windows TA as well as the URL ToolBox application are also required.

#### Known False Positives
Legitimate applications may use random Windows Service names.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | A Windows Service with a suspicious service name was installed on $ComputerName$ |




#### Reference

* [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/randomly_generated_windows_service_name.yml) \| *version*: **1**