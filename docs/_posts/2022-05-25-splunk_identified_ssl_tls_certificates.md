---
title: "Splunk Identified SSL TLS Certificates"
excerpt: "Network Sniffing
"
categories:
  - Network
last_modified_at: 2022-05-25
toc: true
toc_label: ""
tags:
  - Network Sniffing
  - Credential Access
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32151
  - CVE-2022-32152
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic uses tags of SSL, TLS and certificate to identify the usage of the Splunk default certificates being utilized in the environment. Recommended guidance is to utilize valid TLS certificates which documentation may be found in Splunk Docs - https://docs.splunk.com/Documentation/Splunk/8.2.6/Security/AboutsecuringyourSplunkconfigurationwithSSL.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-25
- **Author**: Michael Haag, Splunk
- **ID**: 620fbb89-86fd-4e2e-925f-738374277586


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Credential Access, Discovery |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


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
| [CVE-2022-32151](https://nvd.nist.gov/vuln/detail/CVE-2022-32151) | The httplib and urllib Python libraries that Splunk shipped with Splunk Enterprise did not validate certificates using the certificate authority (CA) certificate stores by default in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203. Python 3 client libraries now verify server certificates by default and use the appropriate CA certificate stores for each library. Apps and add-ons that include their own HTTP libraries are not affected. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation. | 6.4 |
| [CVE-2022-32152](https://nvd.nist.gov/vuln/detail/CVE-2022-32152) | Splunk Enterprise peers in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203 did not validate the TLS certificates during Splunk-to-Splunk communications by default. Splunk peer communications configured properly with valid certificates were not vulnerable. However, an attacker with administrator credentials could add a peer without a valid certificate and connections from misconfigured nodes without valid certificates did not fail by default. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation. | 6.5 |



</div>
</details>

#### Search 

```
tag IN (ssl, tls, certificate) ssl_issuer_common_name=*splunk* 
| stats values(src) AS "Host(s) with Default Cert" count by ssl_issuer ssl_subject_common_name ssl_subject_organization ssl_subject host sourcetype 
| `splunk_identified_ssl_tls_certificates_filter`
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **splunk_identified_ssl_tls_certificates_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* ssl_issuer
* ssl_subject_common_name
* ssl_subject_organization
* ssl_subject
* host
* sourcetype


#### How To Implement
Ingestion of SSL/TLS data is needed and to be tagged properly as ssl, tls or certificate. This data may come from a proxy, zeek, or Splunk Streams. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
False positives will not be present as it is meant to assist with identifying default certificates being utilized.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | The following $dest$ is using the self signed Splunk certificate. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/8.2.6/Security/AboutsecuringyourSplunkconfigurationwithSSL](https://docs.splunk.com/Documentation/Splunk/8.2.6/Security/AboutsecuringyourSplunkconfigurationwithSSL)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1040/ssltls/ssl_splunk.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1040/ssltls/ssl_splunk.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/splunk_identified_ssl_tls_certificates.yml) \| *version*: **1**