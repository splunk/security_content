---
title: "Splunk Digital Certificates Lack of Encryption"
excerpt: "Digital Certificates
"
categories:
  - Application
last_modified_at: 2022-05-26
toc: true
toc_label: ""
tags:
  - Digital Certificates
  - Resource Development
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32151
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

On June 14th, 2022, Splunk released a security advisory relating to the authentication that happens between Universal Forwarders and Deployment Servers. In some circumstances, an unauthenticated client can download forwarder bundles from the Deployment Server. In other circumstances, a client may be allowed to publish a forwarder bundle to other clients, which may allow for arbitrary code execution. The fixes for these require upgrading to at least Splunk 9.0 on the forwarder as well. This is a great opportunity to configure TLS across the environment. This search looks for forwarders that are not using TLS and adds risk to those entities.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-26
- **Author**: Lou Stella, Splunk
- **ID**: 386a7ebc-737b-48cf-9ca8-5405459ed508


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1587.003](https://attack.mitre.org/techniques/T1587/003/) | Digital Certificates | Resource Development |

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
| [CVE-2022-32151](https://nvd.nist.gov/vuln/detail/CVE-2022-32151) | The httplib and urllib Python libraries that Splunk shipped with Splunk Enterprise did not validate certificates using the certificate authority (CA) certificate stores by default in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203. Python 3 client libraries now verify server certificates by default and use the appropriate CA certificate stores for each library. Apps and add-ons that include their own HTTP libraries are not affected. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation. | 6.4 |



</div>
</details>

#### Search 

```
`splunkd` group="tcpin_connections" ssl="false" 
| stats values(sourceIp) latest(fwdType) latest(version) by hostname 
| `splunk_digital_certificates_lack_of_encryption_filter`
```

#### Macros
The SPL above uses the following Macros:
* [splunkd](https://github.com/splunk/security_content/blob/develop/macros/splunkd.yml)

> :information_source:
> **splunk_digital_certificates_lack_of_encryption_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* group
* ssl
* sourceIp
* fwdType
* version
* hostname


#### How To Implement
This anomaly search looks for forwarder connections that are not currently using TLS. It then presents the source IP, the type of forwarder, and the version of the forwarder. You can also remove the "ssl=false" argument from the initial stanza in order to get a full list of all your forwarders that are sending data, and the version of Splunk software they are running, for audit purposes. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
None at this time

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 20.0 | 25 | 80 | $hostname$ is not using TLS when forwarding data |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0607.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0607.html)
* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0601.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0601.html)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1587.003/splunk_fwder/splunkd.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1587.003/splunk_fwder/splunkd.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_digital_certificates_lack_of_encryption.yml) \| *version*: **1**