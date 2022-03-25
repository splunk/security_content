---
title: "Remote Registry Key modifications"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-03-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search monitors for remote modifications to registry keys.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-03-02
- **Author**: Bhavin Patel, Splunk
- **ID**: c9f4b923-f8af-4155-b697-1354f5dcbc5e

#### Search

```

| tstats `security_content_summariesonly` count values(Registry.registry_key_name) as registry_key_name values(Registry.registry_path) as registry_path min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where  Registry.registry_path="\\\\*"  by Registry.dest , Registry.user 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `remote_registry_key_modifications_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `remote_registry_key_modifications_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search, you must populate the `Endpoint` data model. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry. Deprecated because I don't think the logic is right.

#### Known False Positives
This technique may be legitimately used by administrators to modify remote registries, so it's important to filter these events out.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/remote_registry_key_modifications.yml) \| *version*: **3**