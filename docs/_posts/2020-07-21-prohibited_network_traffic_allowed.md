---
title: "Prohibited Network Traffic Allowed"
excerpt: "Exfiltration Over Alternative Protocol"
categories:
  - Network
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Exfiltration Over Alternative Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for network traffic defined by port and transport layer protocol in the Enterprise Security lookup table &#34;lookup_interesting_ports&#34;, that is marked as prohibited, and has an associated &#39;allow&#39; action in the Network_Traffic data model. This could be indicative of a misconfigured network device.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: ce5a0962-849f-4720-a678-753fe6674479


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.action = allowed by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action 
| lookup update=true interesting_ports_lookup dest_port as All_Traffic.dest_port OUTPUT app is_prohibited note transport 
| search is_prohibited=true 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Traffic")` 
| `prohibited_network_traffic_allowed_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `prohibited_network_traffic_allowed_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.action
* All_Traffic.src_ip
* All_Traffic.dest_ip
* All_Traffic.dest_port


#### How To Implement
In order to properly run this search, Splunk needs to ingest data from firewalls or other network control devices that mediate the traffic allowed into an environment. This is necessary so that the search can identify an &#39;action&#39; taken on the traffic of interest. The search requires the Network_Traffic data model be populated.

#### Known False Positives
None identified

#### Associated Analytic story
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)
* [Ransomware](/stories/ransomware)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Delivery
* Command and Control






#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/prohibited_network_traffic_allowed.yml) \| *version*: **2**