---
title: "TOR Traffic"
excerpt: "Application Layer Protocol
, Web Protocols
"
categories:
  - Network
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:
  - Application Layer Protocol
  - Web Protocols
  - Command And Control
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for network traffic identified as The Onion Router (TOR), a benign anonymity network which can be abused for a variety of nefarious purposes.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)

- **Last Updated**: 2020-07-22
- **Author**: David Dorsey, Splunk
- **ID**: ea688274-9c06-4473-b951-e4cb7a5d7a45


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Command And Control |

| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.app=tor AND All_Traffic.action=allowed by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Traffic")` 
| `tor_traffic_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `tor_traffic_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.app
* All_Traffic.action
* All_Traffic.src_ip
* All_Traffic.dest_ip
* All_Traffic.dest_port


#### How To Implement
In order to properly run this search, Splunk needs to ingest data from firewalls or other network control devices that mediate the traffic allowed into an environment. This is necessary so that the search can identify an 'action' taken on the traffic of interest. The search requires the Network_Traffic data model be populated.

#### Known False Positives
None at this time

#### Associated Analytic story
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)
* [Ransomware](/stories/ransomware)
* [NOBELIUM Group](/stories/nobelium_group)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Command & Control



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/tor_traffic.yml) \| *version*: **2**