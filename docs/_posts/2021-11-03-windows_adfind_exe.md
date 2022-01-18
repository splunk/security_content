---
title: "Windows AdFind Exe"
excerpt: "Remote System Discovery"
categories:
  - Endpoint
last_modified_at: 2021-11-03
toc: true
toc_label: ""
tags:
  - Remote System Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the execution of `adfind.exe` with command-line arguments that it uses by default. Specifically the filter or search functions. It also considers the arguments necessary like objectcategory, see readme for more details: https://www.joeware.net/freetools/tools/adfind/usage.htm. This has been seen used before by Wizard Spider, FIN6 and actors whom also launched SUNBURST. AdFind.exe is usually used a recon tool to enumare a domain controller.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-03
- **Author**: Jose Hernandez, Bhavin Patel, Splunk
- **ID**: bd3b0187-189b-46c0-be45-f52da2bae67f


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="* -f *" OR Processes.process="* -b *") AND (Processes.process=*objectcategory* OR Processes.process="* -gcb *" OR Processes.process="* -sc *") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_adfind_exe_filter`
```

#### Associated Analytic Story
* [NOBELIUM Group](/stories/nobelium_group)
* [Domain Trust Discovery](/stories/domain_trust_discovery)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.process
* Processes.dest
* Processes.user
* Processes.process_name
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
administrators rarely use adfind, usually not used for legitimate reasons





#### Reference

* [https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
* [https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html](https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_adfind_exe.yml) \| *version*: **2**