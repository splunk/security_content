---
title: "Detect Traffic Mirroring"
excerpt: "Hardware Additions
, Automated Exfiltration
, Network Denial of Service
, Traffic Duplication
"
categories:
  - Network
last_modified_at: 2020-10-28
toc: true
toc_label: ""
tags:
  - Hardware Additions
  - Automated Exfiltration
  - Network Denial of Service
  - Traffic Duplication
  - Initial Access
  - Exfiltration
  - Impact
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised network infrastructure. Traffic mirroring is a native feature for some network devices and used for network analysis and may be configured to duplicate traffic and forward to one or more destinations for analysis by a network analyzer or other monitoring device.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-10-28
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: 42b3b753-5925-49c5-9742-36fa40a73990


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access |

| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Exfiltration |

| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1020.001](https://attack.mitre.org/techniques/T1020/001/) | Traffic Duplication | Exfiltration |

#### Search

```
`cisco_networks` (facility="MIRROR" mnemonic="ETH_SPAN_SESSION_UP") OR (facility="SPAN" mnemonic="SESSION_UP") OR (facility="SPAN" mnemonic="PKTCAP_START") OR (mnemonic="CFGLOG_LOGGEDCMD" command="monitor session*") 
| stats min(_time) AS firstTime max(_time) AS lastTime count BY host facility mnemonic 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `detect_traffic_mirroring_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cisco_networks](https://github.com/splunk/security_content/blob/develop/macros/cisco_networks.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `detect_traffic_mirroring_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* facility
* mnemonic
* host


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must log with a severity level of minimum "5 - notification". The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices and that the devices have been configured according to the documentation of the Cisco Networks Add-on. Also note that an attacker may disable logging from the device prior to enabling traffic mirroring.

#### Known False Positives
This search will return false positives for any legitimate traffic captures by network administrators.

#### Associated Analytic story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)


#### Kill Chain Phase
* Delivery
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_traffic_mirroring.yml) \| *version*: **1**