---
title: "Detect ARP Poisoning"
excerpt: "Hardware Additions, Network Denial of Service, Man-in-the-Middle, ARP Cache Poisoning"
categories:
  - Network
last_modified_at: 2020-08-11
toc: true
toc_label: ""
tags:
  - Hardware Additions
  - Initial Access
  - Network Denial of Service
  - Impact
  - Man-in-the-Middle
  - Credential Access
  - Collection
  - ARP Cache Poisoning
  - Credential Access
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

By enabling Dynamic ARP Inspection as a Layer 2 Security measure on the organization&#39;s network devices, we will be able to detect ARP Poisoning attacks in the Infrastructure.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-08-11
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: b44bebd6-bd39-467b-9321-73971bcd7aac


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access |

| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1557](https://attack.mitre.org/techniques/T1557/) | Man-in-the-Middle | Credential Access, Collection |

| [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | ARP Cache Poisoning | Credential Access, Collection |

#### Search

```
`cisco_networks` facility="PM" mnemonic="ERR_DISABLE" disable_cause="arp-inspection" 
| eval src_interface=src_int_prefix_long+src_int_suffix 
| stats min(_time) AS firstTime max(_time) AS lastTime count BY host src_interface 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)`
| `detect_arp_poisoning_filter`
```

#### Associated Analytic Story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must be configured with DHCP Snooping (see https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-0_2_EX/security/configuration_guide/b_sec_152ex_2960-x_cg/b_sec_152ex_2960-x_cg_chapter_01101.html) and Dynamic ARP Inspection (see https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/security/configuration_guide/b_sec_1522e_2960x_cg/b_sec_1522e_2960x_cg_chapter_01111.html) and log with a severity level of minimum &#34;5 - notification&#34;. The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices.

#### Required field
* _time
* facility
* mnemonic
* disable_cause
* src_int_prefix_long
* src_int_suffix
* host
* src_interface


#### Kill Chain Phase
* Reconnaissance
* Delivery
* Actions on Objectives


#### Known False Positives
This search might be prone to high false positives if DHCP Snooping or ARP inspection has been incorrectly configured, or if a device normally sends many ARP packets (unlikely).





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_arp_poisoning.yml) \| *version*: **1**