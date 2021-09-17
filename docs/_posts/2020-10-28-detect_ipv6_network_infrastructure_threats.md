---
title: "Detect IPv6 Network Infrastructure Threats"
excerpt: "Hardware Additions, Network Denial of Service, ARP Cache Poisoning"
categories:
  - Network
last_modified_at: 2020-10-28
toc: true
tags:
  - TTP
  - T1200
  - Hardware Additions
  - Initial Access
  - T1498
  - Network Denial of Service
  - Impact
  - T1557.002
  - ARP Cache Poisoning
  - Credential Access
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Reconnaissance
  - Delivery
  - Actions on Objectives
---

# Detect IPv6 Network Infrastructure Threats

By enabling IPv6 First Hop Security as a Layer 2 Security measure on the organization&#39;s network devices, we will be able to detect various attacks such as packet forging in the Infrastructure.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: [T1200](https://attack.mitre.org/techniques/T1200/), [T1498](https://attack.mitre.org/techniques/T1498/), [T1557.002](https://attack.mitre.org/techniques/T1557/002/)
- **Last Updated**: 2020-10-28
- **Author**: Mikael Bjerkeland, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1200 | Hardware Additions | Initial Access |
| T1498 | Network Denial of Service | Impact |
| T1557.002 | ARP Cache Poisoning | Credential Access, Collection |


#### Search

```
`cisco_networks` facility=&#34;SISF&#34; mnemonic IN (&#34;IP_THEFT&#34;,&#34;MAC_THEFT&#34;,&#34;MAC_AND_IP_THEFT&#34;,&#34;PAK_DROP&#34;) 
| eval src_interface=src_int_prefix_long+src_int_suffix 
| eval dest_interface=dest_int_prefix_long+dest_int_suffix 
| stats min(_time) AS firstTime max(_time) AS lastTime values(src_mac) AS src_mac values(src_vlan) AS src_vlan values(mnemonic) AS mnemonic values(vendor_explanation) AS vendor_explanation values(src_ip) AS src_ip values(dest_ip) AS dest_ip values(dest_interface) AS dest_interface values(action) AS action count BY host src_interface 
| table host src_interface dest_interface src_mac src_ip dest_ip src_vlan mnemonic vendor_explanation action count 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `detect_ipv6_network_infrastructure_threats_filter`
```

#### Associated Analytic Story

* [Router and Infrastructure Security](_stories/router_and_infrastructure_security)


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must be configured with one or more First Hop Security measures such as RA Guard, DHCP Guard and/or device tracking. See References for more information. The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices.

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


#### Kill Chain Phase

* Reconnaissance

* Delivery

* Actions on Objectives


#### Known False Positives
None currently known




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
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:21.998946 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```