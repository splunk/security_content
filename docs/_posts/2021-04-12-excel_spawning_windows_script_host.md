---
title: "Excel Spawning Windows Script Host"
excerpt: "Security Account Manager
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2021-04-12
toc: true
toc_label: ""
tags:
  - Security Account Manager
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies Microsoft Excel spawning Windows Script Host - `cscript.exe` or `wscript.exe`. Typically, this is not common behavior and not default with Excel.exe. Excel.exe will generally be found in the following path `C:\Program Files\Microsoft Office\root\Office16` (version will vary). `cscript.exe` or `wscript.exe` default location is `c:\windows\system32\` or c:windows\syswow64`. `cscript.exe` or `wscript.exe` spawning from Excel.exe is common for a spearphishing attachment and is actively used. Albeit, the command-line executed will most likely be obfuscated and captured via another detection. During triage, review parallel processes and identify any files that may have been written. Review the reputation of the remote destination and block accordingly.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-12
- **Author**: Michael Haag, Splunk
- **ID**: 57fe880a-9be3-11eb-9bf3-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

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

| tstats `security_content_summariesonly` count values(Processes.process) min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="excel.exe" Processes.process_name IN ("cscript.exe", "wscript.exe")  by Processes.parent_process Processes.process_name Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `excel_spawning_windows_script_host_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **excel_spawning_windows_script_host_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* process_name
* process_id
* parent_process_name
* dest
* user
* parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
False positives should be limited, but if any are present, filter as needed. In some instances, `cscript.exe` is used for legitimate business practices.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$, indicating potential suspicious macro execution. |


#### Reference

* [https://app.any.run/tasks/8ecfbc29-03d0-421c-a5bf-3905d29192a2/](https://app.any.run/tasks/8ecfbc29-03d0-421c-a5bf-3905d29192a2/)
* [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excel_spawning_windows_script_host.yml) \| *version*: **1**