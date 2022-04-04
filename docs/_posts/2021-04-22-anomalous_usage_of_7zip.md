---
title: "Anomalous usage of 7zip"
excerpt: "Archive via Utility
, Archive Collected Data
"
categories:
  - Endpoint
last_modified_at: 2021-04-22
toc: true
toc_label: ""
tags:
  - Archive via Utility
  - Archive Collected Data
  - Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies a 7z.exe spawned from `Rundll32.exe` or `Dllhost.exe`. It is assumed that the adversary has brought in `7z.exe` and `7z.dll`. It has been observed where an adversary will rename `7z.exe`. Additional coverage may be required to identify the behavior of renamed instances of `7z.exe`. During triage, identify the source of injection into `Rundll32.exe` or `Dllhost.exe`. Capture any files written to disk and analyze as needed. Review parallel processes for additional behaviors. Typically, archiving files will result in exfiltration.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-04-22
- **Author**: Michael Haag, Teoderick Contreras, Splunk
- **ID**: 9364ee8e-a39a-11eb-8f1d-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection |

| [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data | Collection |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("rundll32.exe", "dllhost.exe") Processes.process_name=*7z* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `anomalous_usage_of_7zip_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **anomalous_usage_of_7zip_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
False positives should be limited as this behavior is not normal for `rundll32.exe` or `dllhost.exe` to spawn and run 7zip.

#### Associated Analytic story
* [Cobalt Strike](/stories/cobalt_strike)
* [NOBELIUM Group](/stories/nobelium_group)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$. This behavior is indicative of suspicious loading of 7zip. |


#### Reference

* [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)
* [https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)
* [https://thedfirreport.com/2021/01/31/bazar-no-ryuk/](https://thedfirreport.com/2021/01/31/bazar-no-ryuk/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/anomalous_usage_of_7zip.yml) \| *version*: **1**