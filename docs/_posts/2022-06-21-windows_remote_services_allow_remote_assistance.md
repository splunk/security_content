---
title: "Windows Remote Services Allow Remote Assistance"
excerpt: "Remote Desktop Protocol
, Remote Services
"
categories:
  - Endpoint
last_modified_at: 2022-06-21
toc: true
toc_label: ""
tags:
  - Remote Desktop Protocol
  - Remote Services
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic is to identify a modification in the Windows registry to enable remote desktop assistance on a targeted machine. This technique was seen in several adversaries, malware or red teamer like azorult to remotely access the compromised or targeted host by enabling this protocol in registry. Even this protocol might be allowed in some production environment, This Anomaly behavior is a good pivot to check who and why the user want to enable this feature through registry which is un-common. And as per stated in microsoft documentation the default value of this registry is false that makes this a good indicator of suspicious behavior.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9bce3a97-bc97-4e89-a1aa-ead151c82fbb


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path= "*\\Control\\Terminal Server\\fAllowToGetHelp*" Registry.registry_value_data="0x00000001" by Registry.registry_key_name Registry.user Registry.registry_path Registry.registry_value_data Registry.action Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_remote_services_allow_remote_assistance_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_remote_services_allow_remote_assistance_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.user
* Registry.dest
* Registry.registry_value_name
* Registry.action


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Known False Positives
administrators may enable or disable this feature that may cause some false positive.

#### Associated Analytic story
* [Azorult](/stories/azorult)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | the registry for rdp protocol was modified to enable in $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-remoteassistance-exe-fallowtogethelp](https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-remoteassistance-exe-fallowtogethelp)
* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_remote_services_allow_remote_assistance.yml) \| *version*: **1**