---
title: "Detection of tools built by NirSoft"
excerpt: "Software Deployment Tools"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Software Deployment Tools
  - Execution
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for specific command-line arguments that may indicate the execution of tools made by Nirsoft, which are legitimate, but may be abused by attackers.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 1297fb80-f42a-4q4a-9c8b-78c061417cf6


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1072](https://attack.mitre.org/techniques/T1072/) | Software Deployment Tools | Execution, Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="* /stext *" OR Processes.process="* /scomma *" ) by Processes.parent_process Processes.process_name Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `detection_of_tools_built_by_nirsoft_filter`
```

#### Associated Analytic Story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process
* Processes.parent_process
* Processes.process_name
* Processes.user


#### Kill Chain Phase
* Installation
* Actions on Objectives


#### Known False Positives
While legitimate, these NirSoft tools are prone to abuse. You should verfiy that the tool was used for a legitimate purpose.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/detection_of_tools_built_by_nirsoft.yml) \| *version*: **3**