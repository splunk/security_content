---
title: "Detect ARP Poisoning"
excerpt: "Hardware Additions
, Network Denial of Service
, Adversary-in-the-Middle
, ARP Cache Poisoning
"
categories:
  - Network
last_modified_at: 2020-08-11
toc: true
toc_label: ""
tags:
  - Hardware Additions
  - Network Denial of Service
  - Adversary-in-the-Middle
  - ARP Cache Poisoning
  - Initial Access
  - Impact
  - Collection
  - Credential Access
  - Collection
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

By enabling Dynamic ARP Inspection as a Layer 2 Security measure on the organization's network devices, we will be able to detect ARP Poisoning attacks in the Infrastructure.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-08-11
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: b44bebd6-bd39-467b-9321-73971bcd7aac


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access |

| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Collection, Credential Access |

| [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | ARP Cache Poisoning | Collection, Credential Access |

#### Search

```
`cisco_networks` facility="PM" mnemonic="ERR_DISABLE" disable_cause="arp-inspection" 
| eval src_interface=src_int_prefix_long+src_int_suffix 
| stats min(_time) AS firstTime max(_time) AS lastTime count BY host src_interface 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)`
| `detect_arp_poisoning_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cisco_networks](https://github.com/splunk/security_content/blob/develop/macros/cisco_networks.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `detect_arp_poisoning_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* facility
* mnemonic
* disable_cause
* src_int_prefix_long
* src_int_suffix
* host
* src_interface


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must be configured with DHCP Snooping (see https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-0_2_EX/security/configuration_guide/b_sec_152ex_2960-x_cg/b_sec_152ex_2960-x_cg_chapter_01101.html) and Dynamic ARP Inspection (see https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/security/configuration_guide/b_sec_1522e_2960x_cg/b_sec_1522e_2960x_cg_chapter_01111.html) and log with a severity level of minimum "5 - notification". The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices.

#### Known False Positives
This search might be prone to high false positives if DHCP Snooping or ARP inspection has been incorrectly configured, or if a device normally sends many ARP packets (unlikely).

#### Associated Analytic story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)


#### Kill Chain Phase
* Reconnaissance
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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_arp_poisoning.yml) \| *version*: **1**