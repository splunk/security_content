---
title: "Detect Zerologon via Zeek"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Network
last_modified_at: 2020-09-15
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2020-1472
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects attempts to run exploits for the Zerologon CVE-2020-1472 vulnerability via Zeek RPC

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-09-15
- **Author**: Shannon Davis, Splunk
- **ID**: bf7a06ec-f703-11ea-adc1-0242ac120002


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8
* CIS 11



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472) | An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'. | 9.3 |



</div>
</details>

#### Search

```
`zeek_rpc` operation IN (NetrServerPasswordSet2,NetrServerReqChallenge,NetrServerAuthenticate3) 
| bin span=5m _time 
| stats values(operation) dc(operation) as opscount count(eval(operation=="NetrServerReqChallenge")) as challenge count(eval(operation=="NetrServerAuthenticate3")) as authcount count(eval(operation=="NetrServerPasswordSet2")) as passcount count as totalcount by _time,src_ip,dest_ip 
| search opscount=3 authcount>4 passcount>0 
| search `detect_zerologon_via_zeek_filter`
```

#### Macros
The SPL above uses the following Macros:
* [zeek_rpc](https://github.com/splunk/security_content/blob/develop/macros/zeek_rpc.yml)

Note that **detect_zerologon_via_zeek_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* operation


#### How To Implement
You must be ingesting Zeek DCE-RPC data into Splunk. Zeek data should also be getting ingested in JSON format.  We are detecting when all three RPC operations (NetrServerReqChallenge, NetrServerAuthenticate3, NetrServerPasswordSet2) are splunk_security_essentials_app via bro:rpc:json.  These three operations are then correlated on the Zeek UID field.

#### Known False Positives
unknown

#### Associated Analytic story
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://www.secura.com/blog/zero-logon](https://www.secura.com/blog/zero-logon)
* [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
* [https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_zerologon_via_zeek.yml) \| *version*: **1**