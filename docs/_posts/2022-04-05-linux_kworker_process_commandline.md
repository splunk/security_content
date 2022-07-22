---
title: "Linux Kworker Process CommandLine"
excerpt: "Masquerade Task or Service
, Masquerading
"
categories:
  - Endpoint
last_modified_at: 2022-04-05
toc: true
toc_label: ""
tags:
  - Masquerade Task or Service
  - Masquerading
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for suspicious process kworker commandline in a linux machine. kworker process name or thread are common name of kernel thread in linux process. So it is really a suspicious event a normal user process contain this process commandline. This technique was seen in cyclopsblink malware to blend its core and other of its child process as normal kworker on the compromised machine. This detection might be a good pivot to look for other IOC related to cyclopsblink malware or attacks.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1cefb270-74a5-4e27-aa0c-2b6fa7c5b4ed


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Masquerade Task or Service | Defense Evasion |

| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  Processes.process = "*[kworker/*" OR Processes.parent_process = "*[kworker/*" by  Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_kworker_process_commandline_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **linux_kworker_process_commandline_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
unknown

#### Associated Analytic story
* [Cyclops BLink](/stories/cyclops_blink)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | a $process_name$ with kworker commandline in $dest$ |


#### Reference

* [https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf](https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf)
* [https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html](https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/cyclopsblink/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/cyclopsblink/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_kworker_process_commandline.yml) \| *version*: **1**