---
title: "Excessive DNS Failures"
excerpt: "DNS
, Application Layer Protocol
"
categories:
  - Network
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - DNS
  - Application Layer Protocol
  - Command And Control
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search identifies DNS query failures by counting the number of DNS responses that do not indicate success, and trigger on more than 50 occurrences.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 104658f4-afdc-499e-9719-17243f9826f1


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | Command And Control |

| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Command And Control |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.PT
* DE.AE
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8
* CIS 9
* CIS 12



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count values("DNS.query") as queries from datamodel=Network_Resolution where nodename=DNS "DNS.reply_code"!="No Error" "DNS.reply_code"!="NoError" DNS.reply_code!="unknown" NOT "DNS.query"="*.arpa" "DNS.query"="*.*" by "DNS.src","DNS.query"
| `drop_dm_object_name("DNS")`
| lookup cim_corporate_web_domain_lookup domain as query OUTPUT domain
| where isnull(domain)
| lookup update=true alexa_lookup_by_str domain as query OUTPUT rank
| where isnull(rank)
| stats sum(count) as count mode(queries) as queries by src
| `get_asset(src)`
| where count>50 
| `excessive_dns_failures_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **excessive_dns_failures_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.query
* DNS.reply_code
* DNS.src


#### How To Implement
To successfully implement this search you must ensure that DNS data is populating the Network_Resolution data model.

#### Known False Positives
It is possible legitimate traffic can trigger this rule. Please investigate as appropriate. The threshold for generating an event can also be customized to better suit your environment.

#### Associated Analytic story
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/excessive_dns_failures.yml) \| *version*: **2**