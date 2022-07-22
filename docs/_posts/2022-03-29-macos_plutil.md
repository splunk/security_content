---
title: "MacOS plutil"
excerpt: "Plist Modification
"
categories:
  - Endpoint
last_modified_at: 2022-03-29
toc: true
toc_label: ""
tags:
  - Plist Modification
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

Detect usage of plutil to modify plist files. Adversaries can modiy plist files to executed binaries or add command line arguments. Plist files in auto-run locations are executed upon user logon or system startup.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-29
- **Author**: Patrick Bareiss, Splunk
- **ID**: c11f2b57-92c1-4cd2-b46c-064eafb833ac


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1547.011](https://attack.mitre.org/techniques/T1547/011/) | Plist Modification | Persistence, Privilege Escalation |

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
`osquery` name=es_process_events columns.path=/usr/bin/plutil 
| rename columns.* as * 
| stats count  min(_time) as firstTime max(_time) as lastTime by username host cmdline pid path parent signing_id 
| rename username as User, cmdline as process, path as process_path 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `macos_plutil_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [osquery](https://github.com/splunk/security_content/blob/develop/macros/osquery.yml)

Note that **macos_plutil_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* columns.cmdline
* columns.pid
* columns.parent
* columns.path
* columns.signing_id
* columns.username
* host


#### How To Implement
This detection uses osquery and endpoint security on MacOS. Follow the link in references, which describes how to setup process auditing in MacOS with endpoint security and osquery.

#### Known False Positives
Administrators using plutil to change plist files.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | plutil are executed on $host$ from $user$ |


#### Reference

* [https://osquery.readthedocs.io/en/stable/deployment/process-auditing/](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.011/atomic_red_team/osquery.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.011/atomic_red_team/osquery.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/macos_plutil.yml) \| *version*: **1**