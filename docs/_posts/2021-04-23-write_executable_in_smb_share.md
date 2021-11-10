---
title: "Write Executable in SMB Share"
excerpt: "Remote Services, SMB/Windows Admin Shares"
categories:
  - Endpoint
last_modified_at: 2021-04-23
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - SMB/Windows Admin Shares
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect suspicious dropping or creating an executable file in known sensitive SMB share. This technique is commonly used for lateral movement like how trickbot try to infect other machine in the infected network. This detection catch the access event (FILE WRITE) access to a share.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: f63c34fe-a435-11eb-935a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

#### Search

```
`wineventlog_security` EventCode=5145 Relative_Target_Name IN ("*.exe","*.dll") Object_Type=File Share_Name IN ("\\\\*\\C$","\\\\*\\IPC$","\\\\*\\admin$") Access_Mask= "0x2" 
| stats min(_time) as firstTime max(_time) as lastTime count by EventCode Share_Name Relative_Target_Name Object_Type Access_Mask user src_port Source_Address 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `write_executable_in_smb_share_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 5145 EventCode enabled. The Windows TA is also required. Also enable the object Audit access success/failure in your group policy.

#### Required field
* _time
* EventCode
* Share_Name
* Relative_Target_Name
* Object_Type
* Access_Mask
* user
* src_port
* Source_Address


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | $user$ dropped or created an executable file in known sensitive SMB share.  Share name=$Share_Name$, Target name=$Relative_Target_Name$, and Access mask=$Access_Mask$ |




#### Reference

* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/exe_smbshare/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/exe_smbshare/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/write_executable_in_smb_share.yml) \| *version*: **1**