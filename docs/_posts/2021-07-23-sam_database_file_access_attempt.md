---
title: "SAM Database File Access Attempt"
excerpt: "Security Account Manager"
categories:
  - Endpoint
last_modified_at: 2021-07-23
toc: true
tags:
  - Hunting
  - T1003.002
  - Security Account Manager
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies access to SAM, SYSTEM or SECURITY databases&#39; within the file path of `windows\system32\config` using Windows Security EventCode 4663. This particular behavior is related to credential access, an attempt to either use a Shadow Copy or recent CVE-2021-36934 to access the SAM database. The Security Account Manager (SAM) is a database file in Windows XP, Windows Vista, Windows 7, 8.1 and 10 that stores users&#39; passwords.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-23
- **Author**: Michael Haag, Mauricio Velazco, Splunk
- **ID**: 57551656-ebdb-11eb-afdf-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |


#### Search

```
`wineventlog_security` (EventCode=4663)  process_name!=*\\dllhost.exe Object_Name IN ("*\\Windows\\System32\\config\\SAM*","*\\Windows\\System32\\config\\SYSTEM*","*\\Windows\\System32\\config\\SECURITY*") 
| stats values(Accesses) count by process_name Object_Name  dest user 
| `sam_database_file_access_attempt_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
To successfully implement this search, you must ingest Windows Security Event logs and track event code 4663. For 4663, enable &#34;Audit Object Access&#34; in Group Policy. Then check the two boxes listed for both &#34;Success&#34; and &#34;Failure.&#34;

#### Required field
* _time
* process_name
* Object_Name
* dest
* user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Natively, `dllhost.exe` will access the files. Every environment will have additional native processes that do as well. Filter by process_name. As an aside, one can remove process_name entirely and add `Object_Name=*ShadowCopy*`.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The following process $process_name$ accessed the object $Object_Name$ attempting to gain access to credentials on $dest$ by user $user$. |



#### Reference

* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4663](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4663)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
* [https://github.com/GossiTheDog/HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)
* [https://github.com/JumpsecLabs/Guidance-Advice/tree/main/SAM_Permissions](https://github.com/JumpsecLabs/Guidance-Advice/tree/main/SAM_Permissions)
* [https://en.wikipedia.org/wiki/Security_Account_Manager](https://en.wikipedia.org/wiki/Security_Account_Manager)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/sam_database_file_access_attempt.yml) \| *version*: **1**