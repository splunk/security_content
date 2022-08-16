---
title: "Windows Odbcconf Load Response File"
excerpt: "Odbcconf
"
categories:
  - Endpoint
last_modified_at: 2022-06-30
toc: true
toc_label: ""
tags:
  - Odbcconf
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the odbcconf.exe, Windows Open Database Connectivity utility, loading up a resource file. The file extension is arbitrary and may be named anything. The resource file itself may have different commands supported by Odbcconf to load up a DLL (REGSVR) on disk or additional commands. During triage, review file modifications and parallel processes.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-06-30
- **Author**: Michael Haag, Splunk
- **ID**: 1acafff9-1347-4b40-abae-f35aa4ba85c1


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.008](https://attack.mitre.org/techniques/T1218/008/) | Odbcconf | Defense Evasion |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=odbcconf.exe Processes.process IN ("*-f *","*/f *") Processes.process="*.rsp*"  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_odbcconf_load_response_file_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_odbcconf_load_response_file_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives may be present and filtering may need to occur based on legitimate application usage. Filter as needed.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to circumvent controls. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://strontic.github.io/xcyclopedia/library/odbcconf.exe-07FBA12552331355C103999806627314.html](https://strontic.github.io/xcyclopedia/library/odbcconf.exe-07FBA12552331355C103999806627314.html)
* [https://twitter.com/redcanary/status/1541838407894171650?s=20&t=kp3WBPtfnyA3xW7D7wx0uw](https://twitter.com/redcanary/status/1541838407894171650?s=20&t=kp3WBPtfnyA3xW7D7wx0uw)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.008/atomic_red_team/windows-sysmon-odbc-rsp.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.008/atomic_red_team/windows-sysmon-odbc-rsp.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_odbcconf_load_response_file.yml) \| *version*: **1**