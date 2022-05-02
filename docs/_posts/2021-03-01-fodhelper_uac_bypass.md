---
title: "FodHelper UAC Bypass"
excerpt: "Modify Registry
, Bypass User Account Control
, Abuse Elevation Control Mechanism
"
categories:
  - Endpoint
last_modified_at: 2021-03-01
toc: true
toc_label: ""
tags:
  - Modify Registry
  - Bypass User Account Control
  - Abuse Elevation Control Mechanism
  - Defense Evasion
  - Defense Evasion
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Fodhelper.exe has a known UAC bypass as it attempts to look for specific registry keys upon execution, that do not exist. Therefore, an attacker can write its malicious commands in these registry keys to be executed by fodhelper.exe with the highest privilege. \
1. `HKCU:\Software\Classes\ms-settings\shell\open\command`\
1. `HKCU:\Software\Classes\ms-settings\shell\open\command\DelegateExecute`\
1. `HKCU:\Software\Classes\ms-settings\shell\open\command\(default)`\
Upon triage, fodhelper.exe will have a child process and read access will occur on the registry keys. Isolate the endpoint and review parallel processes for additional behavior.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-03-01
- **Author**: Michael Haag, Splunk
- **ID**: 909f8fd8-7ac8-11eb-a1f3-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Defense Evasion, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=fodhelper.exe by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `fodhelper_uac_bypass_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **fodhelper_uac_bypass_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.parent_process_name
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Limited to no false positives are expected.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [IcedID](/stories/icedid)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | Suspcious registy keys added by process fodhelper.exe (process_id- $process_id), with a parent_process of $parent_process_name$ that has been executed on $dest$ by $user$. |


#### Reference

* [https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/](https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)
* [https://github.com/gushmazuko/WinBypass/blob/master/FodhelperBypass.ps1](https://github.com/gushmazuko/WinBypass/blob/master/FodhelperBypass.ps1)
* [https://attack.mitre.org/techniques/T1548/002](https://attack.mitre.org/techniques/T1548/002)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/fodhelper_uac_bypass.yml) \| *version*: **1**