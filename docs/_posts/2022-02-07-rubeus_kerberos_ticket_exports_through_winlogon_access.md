---
title: "Rubeus Kerberos Ticket Exports Through Winlogon Access"
excerpt: "Use Alternate Authentication Material
, Pass the Ticket
"
categories:
  - Endpoint
last_modified_at: 2022-02-07
toc: true
toc_label: ""
tags:
  - Use Alternate Authentication Material
  - Pass the Ticket
  - Defense Evasion
  - Lateral Movement
  - Defense Evasion
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic looks for a process accessing the winlogon.exe system process. The Splunk Threat Research team identified this behavior when using the Rubeus tool to monitor for and export kerberos tickets from memory. Before being able to export tickets. Rubeus will try to escalate privileges to SYSTEM by obtaining a handle to winlogon.exe before trying to monitor for kerberos tickets. Exporting tickets from memory is typically the first step for pass the ticket attacks. Red teams and adversaries alike may use the pass the ticket technique using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Defenders should be aware that adversaries may customize the source code of Rubeus to potentially bypass this analytic.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-02-07
- **Author**: Mauricio Velazco, Splunk
- **ID**: 5ed8c50a-8869-11ec-876f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Pass the Ticket | Defense Evasion, Lateral Movement |

#### Search

```
 `sysmon` EventCode=10 TargetImage=C:\\Windows\\system32\\winlogon.exe (GrantedAccess=0x1f3fff) (SourceImage!=C:\\Windows\\system32\\svchost.exe AND SourceImage!=C:\\Windows\\system32\\lsass.exe AND SourceImage!=C:\\Windows\\system32\\LogonUI.exe AND SourceImage!=C:\\Windows\\system32\\smss.exe AND SourceImage!=C:\\Windows\\system32\\wbem\\wmiprvse.exe) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SourceImage, SourceProcessId, TargetImage, TargetProcessId, EventCode, GrantedAccess 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `rubeus_kerberos_ticket_exports_through_winlogon_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `rubeus_kerberos_ticket_exports_through_winlogon_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* TargetImage
* CallTrace
* Computer
* TargetProcessId
* SourceImage
* SourceProcessId


#### How To Implement
This search needs Sysmon Logs and a sysmon configuration, which includes EventCode 10. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment.

#### Known False Positives
Legitimate applications may obtain a handle for winlogon.exe. Filter as needed

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | Winlogon.exe was accessed by $SourceImage$ on $dest$ |




#### Reference

* [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
* [http://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/](http://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
* [https://attack.mitre.org/techniques/T1550/003/](https://attack.mitre.org/techniques/T1550/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/rubeus/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/rubeus/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rubeus_kerberos_ticket_exports_through_winlogon_access.yml) \| *version*: **1**