---
title: "Detect Windows DNS SIGRed via Zeek"
excerpt: "Exploitation for Client Execution
"
categories:
  - Network
last_modified_at: 2020-07-28
toc: true
toc_label: ""
tags:
  - Exploitation for Client Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2020-1350
  - Network_Resolution
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects SIGRed via Zeek DNS and Zeek Conn data.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-07-28
- **Author**: Shannon Davis, Splunk
- **ID**: c5c622e4-d073-11ea-87d0-0242ac130003


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | Execution |

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
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2020-1350](https://nvd.nist.gov/vuln/detail/CVE-2020-1350) | A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'. | 10.0 |



</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Network_Resolution where DNS.query_type IN (SIG,KEY) by DNS.flow_id 
| rename DNS.flow_id as flow_id 
| append [
| tstats  `security_content_summariesonly` count from datamodel=Network_Traffic where All_Traffic.bytes_in>65000 by All_Traffic.flow_id 
| rename All_Traffic.flow_id as flow_id] 
| `detect_windows_dns_sigred_via_zeek_filter` 
| stats count by flow_id 
| where count>1 
| fields - count 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **detect_windows_dns_sigred_via_zeek_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.query_type
* DNS.flow_id
* All_Traffic.bytes_in
* All_Traffic.flow_id


#### How To Implement
You must be ingesting Zeek DNS and Zeek Conn data into Splunk. Zeek data should also be getting ingested in JSON format.  We are detecting SIG and KEY records via bro:dns:json and TCP payload over 65KB in size via bro:conn:json.  The Network Resolution and Network Traffic datamodels are in use for this search.

#### Known False Positives
unknown

#### Associated Analytic story
* [Windows DNS SIGRed CVE-2020-1350](/stories/windows_dns_sigred_cve-2020-1350)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_windows_dns_sigred_via_zeek.yml) \| *version*: **1**