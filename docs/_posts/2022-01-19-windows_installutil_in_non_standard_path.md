---
title: "Windows InstallUtil in Non Standard Path"
excerpt: "Masquerading
, Rename System Utilities
, Signed Binary Proxy Execution
, InstallUtil
"
categories:
  - Endpoint
last_modified_at: 2022-01-19
toc: true
toc_label: ""
tags:
  - Masquerading
  - Rename System Utilities
  - Signed Binary Proxy Execution
  - InstallUtil
  - Defense Evasion
  - Defense Evasion
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the Windows binary InstallUtil.exe running from a non-standard location. The analytic utilizes a macro for InstallUtil and identifies both the process_name and original_file_name.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-01-19
- **Author**: Michael Haag, Splunk
- **ID**: dcf74b22-7933-11ec-857c-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | InstallUtil | Defense Evasion |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes where `process_installutil` NOT (Processes.process_path IN ("*\\Windows\\ADWS\\*","*\\Windows\\SysWOW64*", "*\\Windows\\system32*", "*\\Windows\\NetworkController\\*", "*\\Windows\\SystemApps\\*", "*\\WinSxS\\*", "*\\Windows\\Microsoft.NET\\*")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.original_file_name Processes.process_id Processes.parent_process_id Processes.process_hash 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_installutil_in_non_standard_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_installutil](https://github.com/splunk/security_content/blob/develop/macros/process_installutil.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_installutil_in_non_standard_path_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be present and filtering may be required. Certain utilities will run from non-standard paths based on the third-party application in use.

#### Associated Analytic story
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)
* [Unusual Processes](/stories/unusual_processes)
* [Ransomware](/stories/ransomware)
* [Signed Binary Proxy Execution InstallUtil](/stories/signed_binary_proxy_execution_installutil)
* [WhisperGate](/stories/whispergate)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ from a non-standard path was identified on endpoint $dest$ by user $user$. |


#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml)
* [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon_installutil_path.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon_installutil_path.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_installutil_in_non_standard_path.yml) \| *version*: **1**