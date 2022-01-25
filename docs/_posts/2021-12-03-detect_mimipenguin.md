---
title: "Detect MimiPenguin"
excerpt: "Unsecured Credentials"
categories:
  - Endpoint
last_modified_at: 2021-12-03
toc: true
toc_label: ""
tags:
  - Unsecured Credentials
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

MimiPenguin is a tool that dumps login passwords from current linux destop users. This search detects execution of this tool.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-03
- **Author**: Rod Soto
- **ID**: 1ad20afa-547b-11ec-b4e7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Credential Access |

#### Search

```
 `sysmon_linux` CommandLine="strings -e /etc/apache2/apache2.conf" OR CommandLine="strings -e /etc/ssh/sshd_config" OR CommandLine="strings -e /etc/shadow"  
| stats count by Computer parent_process process_current_directory user CommandLine 
| `detect_mimipenguin_filter`
```

#### Associated Analytic Story
* [Linux Post-Exploitation](/stories/linux_post-exploitation)


#### How To Implement
This detection search is based on Splunk add-on for Microsoft Sysmon-Linux. Need to install this add-on to parse fields correctly and execute detection search.

#### Required field
* _time
* user
* Computer
* parent_process
* process_current_directory


#### Kill Chain Phase
* Privilege Escalation


#### Known False Positives
Some of these commands may be executed by sysadmin however not in the proximity and frequency, specially if querying for tools are that knonwn not to be installed at target system.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | MimiPenguin post exploitation tool detected |




#### Reference

* [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin)
* [https://attack.mitre.org/matrices/enterprise/linux/](https://attack.mitre.org/matrices/enterprise/linux/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://github.com/splunk/attack_data/raw/master/datasets/suspicious_behaviour/linux_post_exploitation/mimipenguin.txt](https://github.com/splunk/attack_data/raw/master/datasets/suspicious_behaviour/linux_post_exploitation/mimipenguin.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_mimipenguin.yml) \| *version*: **1**