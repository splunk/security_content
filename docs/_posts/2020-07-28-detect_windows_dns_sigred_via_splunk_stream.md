---
title: "Detect Windows DNS SIGRed via Splunk Stream"
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
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects SIGRed via Splunk Stream.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-28
- **Author**: Shannon Davis, Splunk
- **ID**: babd8d10-d073-11ea-87d0-0242ac130003


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | Execution |

#### Search

```
`stream_dns` 
| spath "query_type{}" 
| search "query_type{}" IN (SIG,KEY) 
| spath protocol_stack 
| search protocol_stack="ip:tcp:dns" 
| append [search `stream_tcp` bytes_out>65000] 
| `detect_windows_dns_sigred_via_splunk_stream_filter` 
| stats count by flow_id 
| where count>1 
| fields - count
```

#### Macros
The SPL above uses the following Macros:
* [stream_tcp](https://github.com/splunk/security_content/blob/develop/macros/stream_tcp.yml)
* [stream_dns](https://github.com/splunk/security_content/blob/develop/macros/stream_dns.yml)

Note that `detect_windows_dns_sigred_via_splunk_stream_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting Splunk Stream DNS and Splunk Stream TCP. We are detecting SIG and KEY records via stream:dns and TCP payload over 65KB in size via stream:tcp.  Replace the macro definitions ('stream:dns' and 'stream:tcp') with configurations for your Splunk environment.

#### Known False Positives
unknown

#### Associated Analytic story
* [Windows DNS SIGRed CVE-2020-1350](/stories/windows_dns_sigred_cve-2020-1350)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2020-1350](https://nvd.nist.gov/vuln/detail/CVE-2020-1350) | A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'. | 10.0 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_windows_dns_sigred_via_splunk_stream.yml) \| *version*: **1**