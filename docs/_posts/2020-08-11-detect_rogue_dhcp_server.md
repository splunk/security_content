---
title: "Detect Rogue DHCP Server"
excerpt: "Hardware Additions
, Network Denial of Service
, Adversary-in-the-Middle
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
  - Initial Access
  - Impact
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

By enabling DHCP Snooping as a Layer 2 Security measure on the organization's network devices, we will be able to detect unauthorized DHCP servers handing out DHCP leases to devices on the network (Man in the Middle attack).

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-08-11
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: 6e1ada88-7a0d-4ac1-92c6-03d354686079


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access |

| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Collection, Credential Access |

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
`cisco_networks` facility="DHCP_SNOOPING" mnemonic="DHCP_SNOOPING_UNTRUSTED_PORT" 
| stats min(_time) AS firstTime max(_time) AS lastTime count values(message_type) AS message_type values(src_mac) AS src_mac BY host 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)`
| `detect_rogue_dhcp_server_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cisco_networks](https://github.com/splunk/security_content/blob/develop/macros/cisco_networks.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_rogue_dhcp_server_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* facility
* mnemonic
* message_type
* src_mac
* host


#### How To Implement
This search uses a standard SPL query on logs from Cisco Network devices. The network devices must be configured with DHCP Snooping enabled (see https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-0_2_EX/security/configuration_guide/b_sec_152ex_2960-x_cg/b_sec_152ex_2960-x_cg_chapter_01101.html) and log with a severity level of minimum "5 - notification". The search also requires that the Cisco Networks Add-on for Splunk (https://splunkbase.splunk.com/app/1467) is used to parse the logs from the Cisco network devices.

#### Known False Positives
This search might be prone to high false positives if DHCP Snooping has been incorrectly configured or in the unlikely event that the DHCP server has been moved to another network interface.

#### Associated Analytic story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_rogue_dhcp_server.yml) \| *version*: **1**