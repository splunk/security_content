---
title: "Open Redirect in Splunk Web"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2017-09-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2016-4859
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to look for evidence of exploitation for CVE-2016-4859, the Splunk Open Redirect Vulnerability.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2017-09-19
- **Author**: Bhavin Patel, Splunk
- **ID**: d199fb99-2312-451a-9daa-e5efa6ed76a7


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* ID.RA
* RS.MI
* PR.PT
* PR.AC
* PR.IP
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 4
* CIS 18



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2016-4859](https://nvd.nist.gov/vuln/detail/CVE-2016-4859) | Open redirect vulnerability in Splunk Enterprise 6.4.x prior to 6.4.3, Splunk Enterprise 6.3.x prior to 6.3.6, Splunk Enterprise 6.2.x prior to 6.2.10, Splunk Enterprise 6.1.x prior to 6.1.11, Splunk Enterprise 6.0.x prior to 6.0.12, Splunk Enterprise 5.0.x prior to 5.0.16 and Splunk Light prior to 6.4.3 allows to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors. | 5.8 |



</div>
</details>

#### Search 

```
index=_internal sourcetype=splunk_web_access return_to="/%09/*" 
| `open_redirect_in_splunk_web_filter`
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **open_redirect_in_splunk_web_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
No extra steps needed to implement this search.

#### Known False Positives
None identified

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/open_redirect_in_splunk_web.yml) \| *version*: **1**