---
title: "Path traversal SPL injection"
excerpt: "File and Directory Discovery
"
categories:
  - Application
last_modified_at: 2022-04-29
toc: true
toc_label: ""
tags:
  - File and Directory Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-26889
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

On May 3rd, 2022, Splunk published a security advisory for a Path traversal in search parameter that can potentiall allow SPL injection. An attacker can cause the application to load data from incorrect endpoints, urls leading to outcomes such as running arbitrary SPL queries.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-04-29
- **Author**: Rod Soto, Splunk
- **ID**: dfe55688-82ed-4d24-a21b-ed8f0e0fda99


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Discovery |

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
| [CVE-2022-26889](https://nvd.nist.gov/vuln/detail/CVE-2022-26889) | In Splunk Enterprise versions before 8.1.2, the uri path to load a relative resource within a web page is vulnerable to path traversal. It allows an attacker to potentially inject arbitrary content into the web page (e.g., HTML Injection, XSS) or bypass SPL safeguards for risky commands. The attack is browser-based. An attacker cannot exploit the attack at will and requires the attacker to initiate a request within the victim's browser (e.g., phishing). | 5.1 |



</div>
</details>

#### Search 

```
 `path_traversal_spl_injection` 
| search "\/..\/..\/..\/..\/..\/..\/..\/..\/..\/"  
| stats count by status clientip method uri_path uri_query 
| `path_traversal_spl_injection_filter`
```

#### Macros
The SPL above uses the following Macros:
* [path_traversal_spl_injection](https://github.com/splunk/security_content/blob/develop/macros/path_traversal_spl_injection.yml)

> :information_source:
> **path_traversal_spl_injection_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* status
* clientip
* method
* uri_path
* uri_query


#### How To Implement
This detection does not require you to ingest any new data. The detection does require the ability to search the _internal index. This search will provide search UI requests with path traversal parameter ("../../../../../../../../../") which shows exploitation attempts.

#### Known False Positives
This search may find additional path traversal exploitation attempts.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | Path traversal exploitation attempt from $clientip$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0506.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0506.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1083/splunk/path_traversal_spl_injection.txt](https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1083/splunk/path_traversal_spl_injection.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/path_traversal_spl_injection.yml) \| *version*: **1**