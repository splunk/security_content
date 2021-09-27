---
title: "Detect Windows DNS SIGRed via Splunk Stream"
excerpt: "Exploitation for Client Execution"
categories:
  - Network
last_modified_at: 2020-07-28
toc: true
tags:
  - TTP
  - T1203
  - Exploitation for Client Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects SIGRed via Splunk Stream.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-28
- **Author**: Shannon Davis, Splunk
- **ID**: babd8d10-d073-11ea-87d0-0242ac130003


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
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

#### Associated Analytic Story
* [Windows DNS SIGRed CVE-2020-1350](/stories/windows_dns_sigred_cve-2020-1350)


#### How To Implement
You must be ingesting Splunk Stream DNS and Splunk Stream TCP. We are detecting SIG and KEY records via stream:dns and TCP payload over 65KB in size via stream:tcp.  Replace the macro definitions (&#39;stream:dns&#39; and &#39;stream:tcp&#39;) with configurations for your Splunk environment.

#### Required field
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown




#### Reference

* [https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/](https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_windows_dns_sigred_via_splunk_stream.yml) \| *version*: **1**