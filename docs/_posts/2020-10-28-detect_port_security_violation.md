---
title: "Detect Port Security Violation"
excerpt: "Hardware Additions, Network Denial of Service, Adversary-in-the-Middle, ARP Cache Poisoning"
categories:
  - Network
last_modified_at: 2020-10-28
toc: true
toc_label: ""
tags:
  - Hardware Additions
  - Initial Access
  - Network Denial of Service
  - Impact
  - Adversary-in-the-Middle
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
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

By enabling Port Security on a Cisco switch you can restrict input to an interface by limiting and identifying MAC addresses of the workstations that are allowed to access the port. When you assign secure MAC addresses to a secure port, the port does not forward packets with source addresses outside the group of defined addresses. If you limit the number of secure MAC addresses to one and assign a single secure MAC address, the workstation attached to that port is assured the full bandwidth of the port. If a port is configured as a secure port and the maximum number of secure MAC addresses is reached, when the MAC address of a workstation attempting to access the port is different from any of the identified secure MAC addresses, a security violation occurs.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-10-28
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: 2de3d5b8-a4fa-45c5-8540-6d071c194d24


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access |

| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Credential Access, Collection |

| [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | ARP Cache Poisoning | Credential Access, Collection |

#### Search

```
`cisco_networks` (facility="PM" mnemonic="ERR_DISABLE" disable_cause="psecure-violation") OR (facility="PORT_SECURITY" mnemonic="PSECURE_VIOLATION" OR mnemonic="PSECURE_VIOLATION_VLAN") 
| eval src_interface=src_int_prefix_long+src_int_suffix 
| stats min(_time) AS firstTime max(_time) AS lastTime values(disable_cause) AS disable_cause values(src_mac) AS src_mac values(src_vlan) AS src_vlan values(action) AS action count by host src_interface 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_port_security_violation_filter`
```

#### Associated Analytic Story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must be configured with Port Security and Error Disable for this to work (see https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/port_sec.html) and log with a severity level of minimum &#34;5 - notification&#34;. The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices.

#### Required field
* _time
* facility
* mnemonic
* disable_cause
* src_int_prefix_long
* src_int_suffix
* src_mac
* src_vlan
* action
* host
* src_interface


#### Kill Chain Phase
* Reconnaissance
* Delivery
* Exploitation
* Actions on Objectives


#### Known False Positives
This search might be prone to high false positives if you have malfunctioning devices connected to your ethernet ports or if end users periodically connect physical devices to the network.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_port_security_violation.yml) \| *version*: **1**