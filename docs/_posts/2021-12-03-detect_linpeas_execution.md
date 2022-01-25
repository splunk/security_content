---
title: "Detect LinPeas Execution"
excerpt: "System Information Discovery, File and Directory Discovery, System Owner/User Discovery, Account Discovery, Network Service Scanning, Process Discovery, Software Discovery, System Owner/User Discovery"
categories:
  - Endpoint
last_modified_at: 2021-12-03
toc: true
toc_label: ""
tags:
  - System Information Discovery
  - Discovery
  - File and Directory Discovery
  - Discovery
  - System Owner/User Discovery
  - Discovery
  - Account Discovery
  - Discovery
  - Network Service Scanning
  - Discovery
  - Process Discovery
  - Discovery
  - Software Discovery
  - Discovery
  - System Owner/User Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Linux local Privilege Escalation Awesome Script (linPEAS) is a script that searches for possible paths to escalate privileges.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-03
- **Author**: Rod Soto
- **ID**: 4ea6fa10-547c-11ec-a4f9-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery |

| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Discovery |

| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Scanning | Discovery |

| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Discovery |

| [T1518](https://attack.mitre.org/techniques/T1518/) | Software Discovery | Discovery |

| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

#### Search

```
 `sysmon_linux` CommandLine!=null parent_process_exec=sudo OR parent_process_exec=bash OR CommandLine="cve-list" 
| stats count by Computer CommandLine user parent_process_exec process_path 
| `detect_linpeas_execution_filter`
```

#### Associated Analytic Story
* [Linux Post-Exploitation](/stories/linux_post-exploitation)


#### How To Implement
This detection search is based on Splunk add-on for Microsoft Sysmon-Linux. Need to install this add-on to parse fields correctly and execute detection search.

#### Required field
* _time
* Computer
* CommandLine
* user
* parent_process_exec
* process_path


#### Kill Chain Phase
* Exploitation
* Privilege Escalation


#### Known False Positives
This search may produce false positives as it will display many sudo executed processess however, the cve-list within the command line it is a clear indicator, operator is searching for local vulnerabilites.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | LinPEAS post exploitation tool detected |




#### Reference

* [https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)
* [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* [https://attack.mitre.org/matrices/enterprise/linux/](https://attack.mitre.org/matrices/enterprise/linux/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://github.com/splunk/attack_data/raw/master/datasets/suspicious_behaviour/linux_post_exploitation/linpeasdataset.txt](https://github.com/splunk/attack_data/raw/master/datasets/suspicious_behaviour/linux_post_exploitation/linpeasdataset.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_linpeas_execution.yml) \| *version*: **1**