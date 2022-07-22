---
title: "Windows Impair Defense Deny Security Software With Applocker"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2022-06-24
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a modification in the Windows registry by the Applocker utility that contains details or registry data values related to denying the execution of several security products. This technique was seen in Azorult malware where it drops an xml Applocker policy that will deny several AV products and then loaded by using PowerShell Applocker commandlet.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: e0b6ca60-9e29-4450-b51a-bba0abae2313


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where (Registry.registry_path= "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects\\*" AND Registry.registry_path= "*}Machine\\Software\\Policies\\Microsoft\\Windows\\SrpV2*") OR Registry.registry_path="*\\Software\\Policies\\Microsoft\\Windows\\SrpV2*" AND Registry.registry_value_data = "*Action\=\"Deny\"*" AND Registry.registry_value_data IN("*O=SYMANTEC*","*O=MCAFEE*","*O=KASPERSKY*","*O=BLEEPING COMPUTER*", "*O=PANDA SECURITY*","*O=SYSTWEAK SOFTWARE*", "*O=TREND MICRO*", "*O=AVAST*", "*O=GRIDINSOFT*", "*O=MICROSOFT*", "*O=NANO SECURITY*", "*O=SUPERANTISPYWARE.COM*", "*O=DOCTOR WEB*", "*O=MALWAREBYTES*", "*O=ESET*", "*O=AVIRA*", "*O=WEBROOT*") by  Registry.user Registry.registry_path Registry.registry_value_data Registry.action Registry.registry_key_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_impair_defense_deny_security_software_with_applocker_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_impair_defense_deny_security_software_with_applocker_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Known False Positives
False positives may be present based on organization use of Applocker. Filter as needed.

#### Associated Analytic story
* [Azorult](/stories/azorult)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 100.0 | 100 | 100 | Applocker registry modification to deny the action of several AV products on $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=11](https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=11)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_impair_defense_deny_security_software_with_applocker.yml) \| *version*: **1**