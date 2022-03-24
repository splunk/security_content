---
title: "Osquery pack - ColdRoot detection"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2019-01-29
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for ColdRoot events from the osx-attacks osquery pack.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2019-01-29
- **Author**: Rico Valdez, Splunk
- **ID**: a6fffe5e-05c3-4c04-badc-887607fbb8dc

#### Search

```

| from datamodel Alerts.Alerts 
| search app=osquery:results (name=pack_osx-attacks_OSX_ColdRoot_RAT_Launchd OR name=pack_osx-attacks_OSX_ColdRoot_RAT_Files) 
| rename columns.path as path 
| bucket _time span=30s 
| stats count(path) by _time, host, user, path 
| `osquery_pack___coldroot_detection_filter`
```

#### Macros
The SPL above uses the following Macros:

Note that `osquery_pack_-_coldroot_detection_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
In order to properly run this search, Splunk needs to ingest data from your osquery deployed agents with the [osx-attacks.conf](https://github.com/facebook/osquery/blob/experimental/packs/osx-attacks.conf#L599) pack enabled. Also the [TA-OSquery](https://github.com/d1vious/TA-osquery) must be deployed across your indexers and universal forwarders in order to have the osquery data populate the Alerts data model

#### Known False Positives
There are no known false positives.

#### Associated Analytic story
* [ColdRoot MacOS RAT](/stories/coldroot_macos_rat)


#### Kill Chain Phase
* Installation
* Command & Control



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/osquery_pack_-_coldroot_detection.yml) \| *version*: **1**