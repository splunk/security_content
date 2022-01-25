---
title: "Detect LinEnum execution"
excerpt: "Account Discovery, Permission Groups Discovery, File and Directory Discovery, Process Discovery, Software Discovery, System Information Discovery, System Network Configuration Discovery, System Owner/User Discovery"
categories:
  - Endpoint
last_modified_at: 2021-12-03
toc: true
toc_label: ""
tags:
  - Account Discovery
  - Discovery
  - Permission Groups Discovery
  - Discovery
  - File and Directory Discovery
  - Discovery
  - Process Discovery
  - Discovery
  - Software Discovery
  - Discovery
  - System Information Discovery
  - Discovery
  - System Network Configuration Discovery
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

LinEnum is a bash script that performs discovery commands for accounts, processes, kernel version, applications, services, and uses the information from these commands to present operator with ways of escalating privileges or further exploitation of targeted host.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-03
- **Author**: Rod Soto
- **ID**: 570e5278-5479-11ec-89c8-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery |

| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Discovery |

| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Discovery |

| [T1518](https://attack.mitre.org/techniques/T1518/) | Software Discovery | Discovery |

| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery |

| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Discovery |

| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

#### Search

```
 `sysmon_linux` CommandLine="grep -w aria2c\\
|arp\\
|ash\\
|awk\\
|base64\\
|bash\\
|busybox\\
|cat\\
|chmod\\
|chown\\
|cp\\
|csh\\
|curl\\
|cut\\
|dash\\
|date\\
|dd\\
|diff\\
|dmsetup\\
|docker\\
|ed\\
|emacs\\
|env\\
|expand\\
|expect\\
|file\\
|find\\
|flock\\
|fmt\\
|fold\\
|ftp\\
|gawk\\
|gdb\\
|gimp\\
|git\\
|grep\\
|head\\
|ht\\
|iftop\\
|ionice\\
|ip$\\
|irb\\
|jjs\\
|jq\\
|jrunscript\\
|ksh\\
|ld.so\\
|ldconfig\\
|less\\
|logsave\\
|lua\\
|make\\
|man\\
|mawk\\
|more\\
|mv\\
|mysql\\
|nano\\
|nawk\\
|nc\\
|netcat\\
|nice\\
|nl\\
|nmap\\
|node\\
|od\\
|openssl\\
|perl\\
|pg\\
|php\\
|pic\\
|pico\\
|python\\
|readelf\\
|rlwrap\\
|rpm\\
|rpmquery\\
|rsync\\
|ruby\\
|run-parts\\
|rvim\\
|scp\\
|script\\
|sed\\
|setarch\\
|sftp\\
|sh\\
|shuf\\
|socat\\
|sort\\
|sqlite3\\
|ssh$\\
|start-stop-daemon\\
|stdbuf\\
|strace\\
|systemctl\\
|tail\\
|tar\\
|taskset\\
|tclsh\\
|tee\\
|telnet\\
|tftp\\
|time\\
|timeout\\
|ul\\
|unexpand\\
|uniq\\
|unshare\\
|vi\\
|vim\\
|watch\\
|wget\\
|wish\\
|xargs\\
|xxd\\
|zip\\
|zsh" 
| stats count by Computer CommandLine user process_exec process_current_directory 
| `detect_linenum_execution_filter` 
```

#### Associated Analytic Story
* [Linux Post-Exploitation](/stories/linux_post-exploitation)


#### How To Implement
This detection search is based on Splunk add-on for Microsoft Sysmon-Linux. Need to install this add-on to parse fields correctly and execute detection search.

#### Required field
* _time
* CommandLine
* user
* process_exec
* process_current_directory


#### Kill Chain Phase
* Privilege Escalation


#### Known False Positives
Very rare to perform such an extensive grep on a system, however certain monitoring tools can produce similar results. It is important if monitoring tools are in place to verify what is the actual process directory of execution.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 50 | 90 | LinEnum post exploitation tool detected |




#### Reference

* [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
* [https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://github.com/splunk/attack_data/raw/master/datasets/suspicious_behaviour/linux_post_exploitation/LinuxEnumd.txt](https://github.com/splunk/attack_data/raw/master/datasets/suspicious_behaviour/linux_post_exploitation/LinuxEnumd.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_linenum_execution.yml) \| *version*: **1**