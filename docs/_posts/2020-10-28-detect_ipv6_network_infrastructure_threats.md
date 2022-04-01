---
title: "Detect IPv6 Network Infrastructure Threats"
excerpt: "Hardware Additions
, Network Denial of Service
, Adversary-in-the-Middle
, ARP Cache Poisoning
"
categories:
  - Network
last_modified_at: 2020-10-28
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

By enabling IPv6 First Hop Security as a Layer 2 Security measure on the organization's network devices, we will be able to detect various attacks such as packet forging in the Infrastructure.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-10-28
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: c3be767e-7959-44c5-8976-0e9c12a91ad2


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access |

| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Collection, Credential Access |

| [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | ARP Cache Poisoning | Collection, Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance
* Delivery
* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* ID.AM
* PR.DS



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 1
* CIS 11



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cisco_networks` facility="SISF" mnemonic IN ("IP_THEFT","MAC_THEFT","MAC_AND_IP_THEFT","PAK_DROP") 
| eval src_interface=src_int_prefix_long+src_int_suffix 
| eval dest_interface=dest_int_prefix_long+dest_int_suffix 
| stats min(_time) AS firstTime max(_time) AS lastTime values(src_mac) AS src_mac values(src_vlan) AS src_vlan values(mnemonic) AS mnemonic values(vendor_explanation) AS vendor_explanation values(src_ip) AS src_ip values(dest_ip) AS dest_ip values(dest_interface) AS dest_interface values(action) AS action count BY host src_interface 
| table host src_interface dest_interface src_mac src_ip dest_ip src_vlan mnemonic vendor_explanation action count 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `detect_ipv6_network_infrastructure_threats_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cisco_networks](https://github.com/splunk/security_content/blob/develop/macros/cisco_networks.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_ipv6_network_infrastructure_threats_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* facility
* mnemonic
* src_int_prefix_long
* src_int_suffix
* dest_int_prefix_long
* dest_int_suffix
* src_mac
* src_vlan
* vendor_explanation
* action


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must be configured with one or more First Hop Security measures such as RA Guard, DHCP Guard and/or device tracking. See References for more information. The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices.

#### Known False Positives
None currently known

#### Associated Analytic story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2019/pdf/BRKSEC-3200.pdf](https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2019/pdf/BRKSEC-3200.pdf)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-ra-guard.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-ra-guard.html)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-snooping.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-snooping.html)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-dad-proxy.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-dad-proxy.html)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-nd-mcast-supp.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-nd-mcast-supp.html)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-dhcpv6-guard.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-dhcpv6-guard.html)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-src-guard.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ip6-src-guard.html)
* [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ipv6-dest-guard.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/xe-16-12/ip6f-xe-16-12-book/ipv6-dest-guard.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_ipv6_network_infrastructure_threats.yml) \| *version*: **1**