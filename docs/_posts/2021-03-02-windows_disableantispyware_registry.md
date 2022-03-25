---
title: "Windows DisableAntiSpyware Registry"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2021-03-02
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for the Registry Key DisableAntiSpyware set to disable. This is consistent with Ryuk infections across a fleet of endpoints. This particular behavior is typically executed when an ransomware actor gains access to an endpoint and beings to perform execution. Usually, a batch (.bat) will be executed and multiple registry and scheduled task modifications will occur. During triage, review parallel processes and identify any further file modifications. Endpoint should be isolated.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-03-02
- **Author**: Rod Soto, Jose Hernandez, Michael Haag, Splunk
- **ID**: 23150a40-9301-4195-b802-5bb4f43067fb


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_value_name="DisableAntiSpyware" AND Registry.registry_value_data="0x00000001" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `windows_disableantispyware_registry_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_disableantispyware_registry_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest
* Registry.user
* Registry.registry_path


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node.

#### Known False Positives
It is unusual to turn this feature off a Windows system since it is a default security control, although it is not rare for some policies to disable it. Although no false positives have been identified, use the provided filter macro to tune the search.

#### Associated Analytic story
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Delivery



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 24.0 | 30 | 80 | Windows DisableAntiSpyware registry key set to 'disabled' on $dest$ |




#### Reference

* [https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/](https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_disableantispyware_registry.yml) \| *version*: **2**