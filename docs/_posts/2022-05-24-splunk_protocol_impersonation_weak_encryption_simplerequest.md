---
title: "Splunk protocol impersonation weak encryption simplerequest"
excerpt: "Digital Certificates
"
categories:
  - Application
last_modified_at: 2022-05-24
toc: true
toc_label: ""
tags:
  - Digital Certificates
  - Resource Development
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32152
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

On Splunk version 9 on Python3 client libraries verify server certificates by default and use CA certificate store. This search warns a user about a failure to validate a certificate using python3 request.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-24
- **Author**: Rod Soto, Splunk
- **ID**: 839d12a6-b119-4d44-ac4f-13eed95412c8


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1588.004](https://attack.mitre.org/techniques/T1588/004/) | Digital Certificates | Resource Development |

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
| [CVE-2022-32152](https://nvd.nist.gov/vuln/detail/CVE-2022-32152) | Splunk Enterprise peers in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203 did not validate the TLS certificates during Splunk-to-Splunk communications by default. Splunk peer communications configured properly with valid certificates were not vulnerable. However, an attacker with administrator credentials could add a peer without a valid certificate and connections from misconfigured nodes without valid certificates did not fail by default. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation. | 6.5 |



</div>
</details>

#### Search 

```
`splunk_python` "simpleRequest SSL certificate validation is enabled without hostname verification" 
| stats count by host path 
| `splunk_protocol_impersonation_weak_encryption_simplerequest_filter`
```

#### Macros
The SPL above uses the following Macros:
* [splunk_python](https://github.com/splunk/security_content/blob/develop/macros/splunk_python.yml)

> :information_source:
> **splunk_protocol_impersonation_weak_encryption_simplerequest_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* host
* event_message
* path


#### How To Implement
Must upgrade to Splunk version 9 and Configure TLS host name validation for Splunk Python modules in order to apply this search. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
This search tries to address validation of server and client certificates within Splunk infrastructure, it might produce results from accidental or unintended requests to port 8089.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | Failed to validate certificate on $host$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/product-security](https://www.splunk.com/en_us/product-security)
* [https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation](https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1558.004/splk_protocol_impersonation_weak_encryption_simplerequest.txt](https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1558.004/splk_protocol_impersonation_weak_encryption_simplerequest.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_protocol_impersonation_weak_encryption_simplerequest.yml) \| *version*: **1**