---
title: "Windows Impair Defense Delete Win Defender Profile Registry"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2022-06-07
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

The search looks for the deletion of Windows Defender main profile within the registry. This was used by RAT malware across a fleet of endpoints. This particular behavior is typically executed when an adversary gains access to an endpoint and beings to perform execution. Usually, a batch (.bat) will be executed and multiple registry and scheduled task modifications will occur. During triage, review parallel processes and identify any further file modifications.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-06-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: 65d4b105-ec52-48ec-ac46-289d0fbf7d96


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

* Delivery


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path = "*\\Policies\\Microsoft\\Windows Defender" Registry.action = deleted by  Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid Registry.action  Registry.user Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_impair_defense_delete_win_defender_profile_registry_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_impair_defense_delete_win_defender_profile_registry_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest
* Registry.user
* Registry.registry_path
* Registry.action


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node.

#### Known False Positives
It is unusual to turn this feature off a Windows system since it is a default security control, although it is not rare for some policies to disable it. Although no false positives have been identified, use the provided filter macro to tune the search.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Windows Registry Abuse](/stories/windows_registry_abuse)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | Windows Defender Logger registry key set to 'disabled' on $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/](https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/)
* [https://app.any.run/tasks/45f5d114-91ea-486c-ab01-41c4093d2861/](https://app.any.run/tasks/45f5d114-91ea-486c-ab01-41c4093d2861/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/delete_win_defender_context_menu/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/delete_win_defender_context_menu/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_impair_defense_delete_win_defender_profile_registry.yml) \| *version*: **1**