---
title: "Windows Possible Credential Dumping"
excerpt: "LSASS Memory
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2022-01-27
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic is an enhanced version of two previous analytics that identifies common GrantedAccess permission requests and CallTrace DLLs in order to detect credential dumping. \
GrantedAccess is the requested permissions by the SourceImage into the TargetImage. \
CallTrace Stack trace of where open process is called. Included is the DLL and the relative virtual address of the functions in the call stack right before the open process call. \
dbgcore.dll or dbghelp.dll  are two core Windows debug DLLs that have minidump functions which provide a way for applications to produce crashdump files that contain a useful subset of the entire process context. \
The idea behind using ntdll.dll is to blend in by using native api of ntdll.dll. For example in sekurlsa module there are many ntdll exported api, like RtlCopyMemory, used to execute this module which is related to lsass dumping.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-01-27
- **Author**: Michael Haag, Splunk
- **ID**: e4723b92-7266-11ec-af45-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.AE
* DE.CM



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
`sysmon` EventCode=10 TargetImage=*lsass.exe GrantedAccess IN ("0x01000", "0x1010", "0x1038", "0x40", "0x1400", "0x1fffff", "0x1410", "0x143a", "0x1438", "0x1000") CallTrace IN ("*dbgcore.dll*", "*dbghelp.dll*", "*ntdll.dll*") 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, TargetImage, GrantedAccess, SourceImage, SourceProcessId, SourceUser, TargetUser 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `windows_possible_credential_dumping_filter`
```

#### Macros
The SPL above uses the following Macros:
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_possible_credential_dumping_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Computer
* TargetImage
* GrantedAccess
* SourceImage
* SourceProcessId
* SourceUser
* TargetUser


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Enabling EventCode 10 TargetProcess lsass.exe is required.

#### Known False Positives
False positives will occur based on GrantedAccess 0x1010 and 0x1400, filter based on source image as needed or remove them. Concern is Cobalt Strike usage of Mimikatz will generate 0x1010 initially, but later be caught.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)
* [DarkSide Ransomware](/stories/darkside_ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A process, $SourceImage$, has loaded $ImageLoaded$ that are typically related to credential dumping on $dest$. Review for further details. |


#### Reference

* [https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
* [https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
* [https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)
* [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)
* [https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights?redirectedfrom=MSDN)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_possible_credential_dumping.yml) \| *version*: **2**