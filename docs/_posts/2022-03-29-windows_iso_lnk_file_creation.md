---
title: "Windows ISO LNK File Creation"
excerpt: "Spearphishing Attachment
, Phishing
, Malicious Link
, User Execution
"
categories:
  - Endpoint
last_modified_at: 2022-03-29
toc: true
toc_label: ""
tags:
  - Spearphishing Attachment
  - Phishing
  - Malicious Link
  - User Execution
  - Initial Access
  - Initial Access
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of a delivered ISO file that has been mounted and the afformention lnk or file opened within it. When the ISO file is opened, the files are saved in the %USER%\AppData\Local\Temp\<random folder name>\ path. The analytic identifies .iso.lnk written to the path. The name of the ISO file is prepended.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-29
- **Author**: Michael Haag, Splunk
- **ID**: d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Malicious Link | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\Microsoft\\Windows\\Recent\\*") Filesystem.file_name IN ("*.iso.lnk") by Filesystem.file_create_time Filesystem.process_id Filesystem.file_name Filesystem.file_path Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_iso_lnk_file_creation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_iso_lnk_file_creation_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* Filesystem.file_create_time
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.file_path
* Filesystem.dest


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be high depending on the environment and consistent use of ISOs mounting. Restrict to servers, or filter out based on commonly used ISO names. Filter as needed.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 80 | 50 | An ISO file was mounted on $dest$ and should be reviewed and filtered as needed. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)
* [https://github.com/MHaggis/notes/blob/master/utilities/ISOBuilder.ps1](https://github.com/MHaggis/notes/blob/master/utilities/ISOBuilder.ps1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.001/atomic_red_team/iso_windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.001/atomic_red_team/iso_windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_iso_lnk_file_creation.yml) \| *version*: **1**