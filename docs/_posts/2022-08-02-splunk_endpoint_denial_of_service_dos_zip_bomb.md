---
title: "Splunk Endpoint Denial of Service DoS Zip Bomb"
excerpt: "Endpoint Denial of Service
"
categories:
  - Application
last_modified_at: 2022-08-02
toc: true
toc_label: ""
tags:
  - Endpoint Denial of Service
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - 
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search allows operator to identify Splunk search app crashes resulting from specially crafted ZIP file using file monitoring that affects UF versions 8.1.11 and 8.2 versions below 8.2.7.1. It is not possible to detect Zip Bomb attack before crash. This search will provide Universal Forwarder errors from uploaded binary files (zip compression) which are used for this attack. If an analyst sees results from this search we suggest you investigate and triage what zip file was uploaded, zip compressed files may have different extensions.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-08-02
- **Author**: Marissa Bower, Rod Soto, Splunk
- **ID**: b237d393-2f57-4531-aad7-ad3c17c8b041


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | Impact |

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
`splunkd` component=FileClassifierManager event_message=*invalid* event_message=*binary* 
|stats count by host component event_message 
| `splunk_endpoint_denial_of_service_dos_zip_bomb_filter`
```

#### Macros
The SPL above uses the following Macros:
* [splunkd](https://github.com/splunk/security_content/blob/develop/macros/splunkd.yml)

> :information_source:
> **splunk_endpoint_denial_of_service_dos_zip_bomb_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* source
* component
* event_message
* host


#### How To Implement
Need to monitor Splunkd data from Universal Forwarders.

#### Known False Positives
This search may reveal non malicious zip files causing errors as well.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 75.0 | 100 | 75 | Potential exposure of environment variables from url embedded in dashboard |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://en.wikipedia.org/wiki/ZIP_(file_format)](https://en.wikipedia.org/wiki/ZIP_(file_format))
* [https://www.splunk.com/en_us/product-security.html](https://www.splunk.com/en_us/product-security.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1499/splunk/splunk_zip_bomb_vulnerability.log](https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1499/splunk/splunk_zip_bomb_vulnerability.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_endpoint_denial_of_service_dos_zip_bomb.yml) \| *version*: **1**