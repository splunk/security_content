---
title: "Attacker Tools On Endpoint"
excerpt: "Match Legitimate Name or Location, Masquerading, OS Credential Dumping, Active Scanning"
categories:
  - Endpoint
last_modified_at: 2021-11-04
toc: true
toc_label: ""
tags:
  - Match Legitimate Name or Location
  - Defense Evasion
  - Masquerading
  - Defense Evasion
  - OS Credential Dumping
  - Credential Access
  - Active Scanning
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for execution of commonly used attacker tools on an endpoint.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-04
- **Author**: Bhavin Patel, Splunk
- **ID**: a51bfe1a-94f0-48cc-b4e4-16a110145893


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Name or Location | Defense Evasion |

| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

| [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | Reconnaissance |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.dest!=unknown Processes.user!=unknown by Processes.dest Processes.user Processes.process_name Processes.process 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| lookup attacker_tools attacker_tool_names AS process_name OUTPUT description 
| search description !=false
| `attacker_tools_on_endpoint_filter`
```

#### Associated Analytic Story
* [Monitor for Unauthorized Software](/stories/monitor_for_unauthorized_software)
* [XMRig](/stories/xmrig)
* [SamSam Ransomware](/stories/samsam_ransomware)
* [Unusual Processes](/stories/unusual_processes)


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model in the processes node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is usually generated via logs that report process tracking in your Windows audit settings.

#### Required field
* Processes.dest
* Processes.user
* Processes.process_name
* Processes.parent_process


#### Kill Chain Phase
* Installation
* Command and Control
* Actions on Objectives


#### Known False Positives
Some administrator activity can be potentially triggered, please add those users to the filter macro.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | An attacker tool $process_name$,listed in attacker_tools.csv is executed on host $dest$ by User $user$. This process $process_name$ is known to do- $description$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1595/attacker_scan_tools/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1595/attacker_scan_tools/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/attacker_tools_on_endpoint.yml) \| *version*: **2**