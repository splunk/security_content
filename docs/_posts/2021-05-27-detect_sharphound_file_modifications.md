---
title: "Detect SharpHound File Modifications"
excerpt: "Domain Account
, Local Groups
, Domain Trust Discovery
, Local Account
, Account Discovery
, Domain Groups
, Permission Groups Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-05-27
toc: true
toc_label: ""
tags:
  - Domain Account
  - Local Groups
  - Domain Trust Discovery
  - Local Account
  - Account Discovery
  - Domain Groups
  - Permission Groups Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

SharpHound is used as a reconnaissance collector, ingestor, for BloodHound. SharpHound will query the domain controller and begin gathering all the data related to the domain and trusts. For output, it will drop a .zip file upon completion following a typical pattern that is often not changed. This analytic focuses on the default file name scheme. Note that this may be evaded with different parameters within SharpHound, but that depends on the operator. `-randomizefilenames` and `-encryptzip` are two examples. In addition, executing SharpHound via .exe or .ps1 without any command-line arguments will still perform activity and dump output to the default filename. Example default filename `20210601181553_BloodHound.zip`. SharpHound creates multiple temp files following the same pattern `20210601182121_computers.json`, `domains.json`, `gpos.json`, `ous.json` and `users.json`. Tuning may be required, or remove these json's entirely if it is too noisy. During traige, review parallel processes for further suspicious behavior. Typically, the process executing the `.ps1` ingestor will be PowerShell.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-27
- **Author**: Michael Haag, Splunk
- **ID**: 42b4b438-beed-11eb-ba1d-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |

| [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Local Groups | Discovery |

| [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery |

| [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Local Account | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery |

| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*bloodhound.zip", "*_computers.json", "*_gpos.json", "*_domains.json", "*_users.json", "*_groups.json") by Filesystem.file_create_time Filesystem.process_id  Filesystem.file_name Filesystem.file_path Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_sharphound_file_modifications_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_sharphound_file_modifications_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* file_path
* dest
* file_name
* process_id
* file_create_time


#### How To Implement
To successfully implement this search you need to be ingesting information on file modifications that include the name of the process, and file, responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.

#### Known False Positives
False positives should be limited as the analytic is specific to a filename with extension .zip. Filter as needed.

#### Associated Analytic story
* [Discovery Techniques](/stories/discovery_techniques)
* [Ransomware](/stories/ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 24.0 | 30 | 80 | Potential SharpHound file modifications identified on $dest$ |


#### Reference

* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)
* [https://thedfirreport.com/?s=bloodhound](https://thedfirreport.com/?s=bloodhound)
* [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
* [https://github.com/BloodHoundAD/SharpHound3](https://github.com/BloodHoundAD/SharpHound3)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-2---run-bloodhound-from-local-disk](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-2---run-bloodhound-from-local-disk)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_sharphound_file_modifications.yml) \| *version*: **1**