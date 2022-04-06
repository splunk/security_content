---
title: "Executable File Written in Administrative SMB Share"
excerpt: "Remote Services
, SMB/Windows Admin Shares
"
categories:
  - Endpoint
last_modified_at: 2021-11-18
toc: true
toc_label: ""
tags:
  - Remote Services
  - SMB/Windows Admin Shares
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies executable files (.exe or .dll) being written to Windows administrative SMB shares (Admin$, IPC$, C$). This represents suspicious behavior as its commonly used by tools like like PsExec/PaExec and others to stage service binaries before creating and starting a Windows service on remote endpoints. Red Teams and adversaries alike may abuse administrative shares for lateral movement and remote code execution. The Trickbot malware family also implements this behavior to try to infect other machines in the infected network.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-11-18
- **Author**: Teoderick Contreras, Mauricio Velazco, Splunk
- **ID**: f63c34fe-a435-11eb-935a-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`wineventlog_security` EventCode=5145 Relative_Target_Name IN ("*.exe","*.dll") Object_Type=File Share_Name IN ("\\\\*\\C$","\\\\*\\IPC$","\\\\*\\admin$") Access_Mask= "0x2" 
| stats min(_time) as firstTime max(_time) as lastTime count by EventCode Share_Name Relative_Target_Name Object_Type Access_Mask user src_port Source_Address 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `executable_file_written_in_administrative_smb_share_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **executable_file_written_in_administrative_smb_share_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 5145 EventCode enabled. The Windows TA is also required. Also enable the object Audit access success/failure in your group policy.

#### Known False Positives
System Administrators may use looks like PsExec for troubleshooting or administrations tasks. However, this will typically come only from certain users and certain systems that can be added to an allow list.

#### Associated Analytic story
* [Data Destruction](/stories/data_destruction)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)
* [Trickbot](/stories/trickbot)
* [Hermetic Wiper](/stories/hermetic_wiper)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | $user$ dropped or created an executable file in known sensitive SMB share.  Share name=$Share_Name$, Target name=$Relative_Target_Name$, and Access mask=$Access_Mask$ |


#### Reference

* [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)
* [https://www.rapid7.com/blog/post/2013/03/09/psexec-demystified/](https://www.rapid7.com/blog/post/2013/03/09/psexec-demystified/)
* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/exe_smbshare/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/exe_smbshare/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/executable_file_written_in_administrative_smb_share.yml) \| *version*: **2**