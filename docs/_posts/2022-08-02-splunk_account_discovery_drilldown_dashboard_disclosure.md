---
title: "Splunk Account Discovery Drilldown Dashboard Disclosure"
excerpt: "Account Discovery
"
categories:
  - Application
last_modified_at: 2022-08-02
toc: true
toc_label: ""
tags:
  - Account Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - 
---

### :warning: WARNING THIS IS A EXPERIMENTAL analytic
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

Splunk drilldown vulnerability disclosure in Dashboard application that can potentially allow exposure of tokens from privilege users. An attacker can create dashboard and share it to privileged user (admin) and detokenize variables using external urls within dashboards drilldown function.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-08-02
- **Author**: Marissa Bower, Rod Soto, Splunk
- **ID**: f844c3f6-fd99-43a2-ba24-93e35fe84be6


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [](https://nvd.nist.gov/vuln/detail/) |  |  |



</div>
</details>

#### Search 

```

| rest splunk_server=local /servicesNS/-/-/data/ui/views 
| search eai:data="*$env:*" eai:data="*url*" eai:data="*options*" 
| rename author AS Author eai:acl.sharing AS Permissions eai:appName AS App eai:data AS "Dashboard XML" 
| fields Author Permissions App "Dashboard XML" 
| `splunk_drilldown_dashboard_disclosure_filter`
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **splunk_account_discovery_drilldown_dashboard_disclosure_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* eai:data
* splunk_server
* author
* eai:acl.sharing
* eai:appName


#### How To Implement
This search uses REST function to query for dashboards with environment variables present in URL options.

#### Known False Positives
This search may reveal non malicious URLs with environment variables used in organizations.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | Potential exposure of environment variables from url embedded in dashboard |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/product-security.html](https://www.splunk.com/en_us/product-security.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/splunk_account_discovery_drilldown_dashboard_disclosure.yml) \| *version*: **1**