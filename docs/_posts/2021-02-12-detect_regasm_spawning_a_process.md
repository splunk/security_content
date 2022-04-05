---
title: "Detect Regasm Spawning a Process"
excerpt: "Signed Binary Proxy Execution
, Regsvcs/Regasm
"
categories:
  - Endpoint
last_modified_at: 2021-02-12
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Regsvcs/Regasm
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies regasm.exe spawning a process. This particular technique has been used in the wild to bypass application control products. Regasm.exe and Regsvcs.exe are signed by Microsoft. Spawning of a child process is rare from either process and should be investigated further. During investigation, identify and retrieve the content being loaded. Review parallel processes for additional suspicious behavior. Gather any other file modifications and review accordingly. regsvcs.exe and regasm.exe are natively found in C:\Windows\Microsoft.NET\Framework\v*\regasm|regsvcs.exe and C:\Windows\Microsoft.NET\Framework64\v*\regasm|regsvcs.exe.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-02-12
- **Author**: Michael Haag, Splunk
- **ID**: 72170ec5-f7d2-42f5-aefb-2b8be6aad15f


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.009](https://attack.mitre.org/techniques/T1218/009/) | Regsvcs/Regasm | Defense Evasion |

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
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=regasm.exe by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_regasm_spawning_a_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_regasm_spawning_a_process_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.parent_process_name
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Although unlikely, limited instances of regasm.exe or regsvcs.exe may cause a false positive. Filter based endpoint usage, command line arguments, or process lineage.

#### Associated Analytic story
* [Suspicious Regsvcs Regasm Activity](/stories/suspicious_regsvcs_regasm_activity)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ spawning a child process, typically not normal behavior for $parent_process_name$. |


#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/](https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/)
* [https://lolbas-project.github.io/lolbas/Binaries/Regasm/](https://lolbas-project.github.io/lolbas/Binaries/Regasm/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_regasm_spawning_a_process.yml) \| *version*: **1**