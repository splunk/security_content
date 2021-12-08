---
title: "Detect Windows DNS SIGRed via Zeek"
excerpt: "Exploitation for Client Execution"
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects SIGRed via Zeek DNS and Zeek Conn data.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-07-28
- **Author**: Shannon Davis, Splunk
- **ID**: c5c622e4-d073-11ea-87d0-0242ac130003


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | Execution |

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

#### Associated Analytic Story
* [Windows DNS SIGRed CVE-2020-1350](/stories/windows_dns_sigred_cve-2020-1350)


#### How To Implement
You must be ingesting Zeek DNS and Zeek Conn data into Splunk. Zeek data should also be getting ingested in JSON format.  We are detecting SIG and KEY records via bro:dns:json and TCP payload over 65KB in size via bro:conn:json.  The Network Resolution and Network Traffic datamodels are in use for this search.

#### Required field
* _time
* DNS.query_type
* DNS.flow_id
* All_Traffic.bytes_in
* All_Traffic.flow_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown




#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2020-1350](https://nvd.nist.gov/vuln/detail/CVE-2020-1350) | A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka &#39;Windows DNS Server Remote Code Execution Vulnerability&#39;. | 10.0 |



#### Reference

* [https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/](https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_windows_dns_sigred_via_zeek.yml) \| *version*: **1**