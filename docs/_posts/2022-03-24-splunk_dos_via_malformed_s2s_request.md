---
title: "Splunk DoS via Malformed S2S Request"
excerpt: "Network Denial of Service
"
categories:
  - Application
last_modified_at: 2022-03-24
toc: true
toc_label: ""
tags:
  - Network Denial of Service
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-3422
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

On March 24th, 2022, Splunk published a security advisory for a possible Denial of Service stemming from the lack of validation in a specific key-value field in the Splunk-to-Splunk (S2S) protocol. This detection will alert on attempted exploitation in patched versions of Splunk.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-24
- **Author**: Lou Stella, Splunk
- **ID**: fc246e56-953b-40c1-8634-868f9e474cbd


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

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
| [CVE-2021-3422](https://nvd.nist.gov/vuln/detail/CVE-2021-3422) | The lack of validation of a key-value field in the Splunk-to-Splunk protocol results in a denial-of-service in Splunk Enterprise instances configured to index Universal Forwarder traffic. The vulnerability impacts Splunk Enterprise versions before 7.3.9, 8.0 versions before 8.0.9, and 8.1 versions before 8.1.3. It does not impact Universal Forwarders. When Splunk forwarding is secured using TLS or a Token, the attack requires compromising the certificate or token, or both. Implementation of either or both reduces the severity to Medium. | None |



</div>
</details>

#### Search

```
`splunkd` log_level=ERROR component=TcpInputProc thread_name=FwdDataReceiverThread 
| table host, src 
| `splunk_dos_via_malformed_s2s_request_filter`
```

#### Macros
The SPL above uses the following Macros:
* [splunkd](https://github.com/splunk/security_content/blob/develop/macros/splunkd.yml)

Note that **splunk_dos_via_malformed_s2s_request_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* host
* src
* log_level
* component
* thread_name


#### How To Implement
This detection does not require you to ingest any new data. The detection does require the ability to search the _internal index. This detection will only find attempted exploitation on versions of Splunk already patched for CVE-2021-3422.

#### Known False Positives
None.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 50.0 | 50 | 100 | An attempt to exploit CVE-2021-3422 was detected from $src$ against $host$ |


#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0301.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0301.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1498/splunk_indexer_dos/splunkd.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1498/splunk_indexer_dos/splunkd.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_dos_via_malformed_s2s_request.yml) \| *version*: **1**