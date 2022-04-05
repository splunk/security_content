---
title: "Spectre and Meltdown Vulnerable Systems"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2017-01-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2017-5753
  - Vulnerabilities
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search is used to detect systems that are still vulnerable to the Spectre and Meltdown vulnerabilities.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Vulnerabilities](https://docs.splunk.com/Documentation/CIM/latest/User/Vulnerabilities)
- **Last Updated**: 2017-01-07
- **Author**: David Dorsey, Splunk
- **ID**: 354be8e0-32cd-4da0-8c47-796de13b60ea


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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

* ID.RA
* RS.MI
* PR.IP
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 4



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2017-5753](https://nvd.nist.gov/vuln/detail/CVE-2017-5753) | Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis. | 4.7 |



</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve ="CVE-2017-5753" OR Vulnerabilities.cve ="CVE-2017-5715" OR Vulnerabilities.cve ="CVE-2017-5754" by Vulnerabilities.dest 
| `drop_dm_object_name(Vulnerabilities)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `spectre_and_meltdown_vulnerable_systems_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **spectre_and_meltdown_vulnerable_systems_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
The search requires that you are ingesting your vulnerability-scanner data and that it reports the CVE of the vulnerability identified.

#### Known False Positives
It is possible that your vulnerability scanner is not detecting that the patches have been applied.

#### Associated Analytic story
* [Spectre And Meltdown Vulnerabilities](/stories/spectre_and_meltdown_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/spectre_and_meltdown_vulnerable_systems.yml) \| *version*: **1**