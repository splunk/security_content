---
title: "Detect Activity Related to Pass the Hash Attacks"
excerpt: "Use Alternate Authentication Material
, Pass the Hash
"
categories:
  - Endpoint
last_modified_at: 2020-10-15
toc: true
toc_label: ""
tags:
  - Use Alternate Authentication Material
  - Pass the Hash
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

This search looks for specific authentication events from the Windows Security Event logs to detect potential attempts at using the Pass-the-Hash technique.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-10-15
- **Author**: Bhavin Patel, Patrick Bareiss, Splunk
- **ID**: f5939373-8054-40ad-8c64-cec478a22a4b


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | Defense Evasion, Lateral Movement |

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

* PR.PT
* PR.AT
* PR.AC
* PR.IP



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
`wineventlog_security` EventCode=4624 (Logon_Type=3 Logon_Process=NtLmSsp WorkstationName=WORKSTATION NOT AccountName="ANONYMOUS LOGON") OR (Logon_Type=9 Logon_Process=seclogo) 
| fillnull 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode, Logon_Type, WorkstationName, user, dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_activity_related_to_pass_the_hash_attacks_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_activity_related_to_pass_the_hash_attacks_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Logon_Type
* Logon_Process
* WorkstationName
* user
* dest


#### How To Implement
To successfully implement this search, you must ingest your Windows Security Event logs and leverage the latest TA for Windows.

#### Known False Positives
Legitimate logon activity by authorized NTLM systems may be detected by this search. Please investigate as appropriate.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | The following $EventCode$ occurred on $dest$ by $user$ with Logon Type 3, which may be indicative of the pass the hash technique. |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.002/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.002/atomic_red_team/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_activity_related_to_pass_the_hash_attacks.yml) \| *version*: **5**