---
title: "Windows Terminating Lsass Process"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2022-03-28
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious process terminating Lsass process. Lsass process is known to be a critical process that is responsible for enforcing security policy system. This process was commonly targetted by threat actor or red teamer to gain privilege escalation or persistence in the targeted machine because it handles credentials of the logon users. In this analytic we tried to detect a suspicious process having a granted access PROCESS_TERMINATE to lsass process to modify or delete protected registrys. This technique was seen in doublezero malware that tries to wipe files and registry in compromised hosts. This anomaly detection can be a good pivot of incident response for possible credential dumping or evading security policy in a host or network environment.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7ab3c319-a4e7-4211-9e8c-40a049d0dba6


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">



</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`sysmon` EventCode=10 TargetImage=*lsass.exe GrantedAccess = 0x1 
| stats count min(_time) as firstTime max(_time) as lastTime by SourceImage, TargetImage, TargetProcessId, SourceProcessId, GrantedAccess CallTrace, Computer 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_terminating_lsass_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_terminating_lsass_process_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* TargetImage
* CallTrace
* Computer
* TargetProcessId
* SourceImage
* SourceProcessId
* GrantedAccess


#### How To Implement
This search requires Sysmon Logs and a Sysmon configuration, which includes EventCode 10 for lsass.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Known False Positives
unknown

#### Associated Analytic story
* [Double Zero Destructor](/stories/double_zero_destructor)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | a process $SourceImage$ terminates Lsass process in $dest$ |


#### Reference

* [https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html](https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/doublezero_wiper/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/doublezero_wiper/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_terminating_lsass_process.yml) \| *version*: **1**