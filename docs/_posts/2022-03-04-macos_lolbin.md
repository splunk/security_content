---
title: "MacOS LOLbin"
excerpt: "Unix Shell
, Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-03-04
toc: true
toc_label: ""
tags:
  - Unix Shell
  - Command and Scripting Interpreter
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Detect multiple executions of Living off the Land (LOLbin) binaries in a short period of time.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-04
- **Author**: Patrick Bareiss, Splunk
- **ID**: 58d270fb-5b39-418e-a855-4b8ac046805e


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

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
`osquery` name=es_process_events columns.cmdline IN ("find*", "crontab*", "screencapture*", "openssl*", "curl*", "wget*", "killall*", "funzip*") 
| rename columns.* as * 
| stats  min(_time) as firstTime max(_time) as lastTime values(cmdline) as cmdline, values(pid) as pid, values(parent) as parent, values(path) as path, values(signing_id) as signing_id,  dc(path) as dc_path by username host 
| rename username as User, cmdline as process, path as process_path 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `macos_lolbin_filter`
```

#### Macros
The SPL above uses the following Macros:
* [osquery](https://github.com/splunk/security_content/blob/develop/macros/osquery.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **macos_lolbin_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
None identified.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | Multiplle LOLbin are executed on host $host$ by user $user$ |


#### Reference

* [https://osquery.readthedocs.io/en/stable/deployment/process-auditing/](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/macos_lolbin/osquery.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/macos_lolbin/osquery.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/macos_lolbin.yml) \| *version*: **1**