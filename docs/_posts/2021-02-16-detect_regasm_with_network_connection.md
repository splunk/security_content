---
title: "Detect Regasm with Network Connection"
excerpt: "Signed Binary Proxy Execution, Regsvcs/Regasm"
categories:
  - Endpoint
last_modified_at: 2021-02-16
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Regsvcs/Regasm
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies regasm.exe with a network connection to a public IP address, exluding private IP space. This particular technique has been used in the wild to bypass application control products. Regasm.exe and Regsvcs.exe are signed by Microsoft. By contacting a remote command and control server, the adversary will have the ability to escalate privileges and complete the objectives. During investigation, identify and retrieve the content being loaded. Review parallel processes for additional suspicious behavior. Gather any other file modifications and review accordingly. Review the reputation of the remote IP or domain and block as needed. regsvcs.exe and regasm.exe are natively found in C:\Windows\Microsoft.NET\Framework\v*\regasm|regsvcs.exe and C:\Windows\Microsoft.NET\Framework64\v*\regasm|regsvcs.exe.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-16
- **Author**: Michael Haag, Splunk
- **ID**: 07921114-6db4-4e2e-ae58-3ea8a52ae93f


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.009](https://attack.mitre.org/techniques/T1218/009/) | Regsvcs/Regasm | Defense Evasion |

#### Search

```
`sysmon` EventID=3 dest_ip!=10.0.0.0/12 dest_ip!=172.16.0.0/12 dest_ip!=192.168.0.0/16 process_name=regasm.exe 
| rename Computer as dest 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, User, process_name, src_ip, dest_host, dest_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_regasm_with_network_connection_filter`
```

#### Associated Analytic Story
* [Suspicious Regsvcs Regasm Activity](/stories/suspicious_regsvcs_regasm_activity)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* EventID
* dest_ip
* process_name
* Computer
* User
* src_ip
* dest_host
* dest_ip


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, limited instances of regasm.exe with a network connection may cause a false positive. Filter based endpoint usage, command line arguments, or process lineage.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $process_name$ contacting a remote destination was identified on endpoint $Computer$ by user $user$. This behavior is not normal for $process_name$. |




#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regasm/](https://lolbas-project.github.io/lolbas/Binaries/Regasm/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_regasm_with_network_connection.yml) \| *version*: **1**