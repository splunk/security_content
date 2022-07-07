---
title: "Splunk Digital Certificates Infrastructure Version"
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
  - CVE-2022-32153
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search will check the TLS validation is properly configured on the search head it is run from as well as its search peers after Splunk version 9. Other components such as additional search heads or anything this rest command cannot be distributed to will need to be manually checked.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-26
- **Author**: Lou Stella, Splunk
- **ID**: 3c162281-7edb-4ebc-b9a4-5087aaf28fa7


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
| [CVE-2022-32153](https://nvd.nist.gov/vuln/detail/CVE-2022-32153) | Splunk Enterprise peers in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203 did not validate the TLS certificates during Splunk-to-Splunk communications by default. Splunk peer communications configured properly with valid certificates were not vulnerable. However, an attacker with administrator credentials could add a peer without a valid certificate and connections from misconfigured nodes without valid certificates did not fail by default. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation. | 6.8 |



</div>
</details>

#### Search 

```

| rest /services/server/info 
| table splunk_server version server_roles 
| join splunk_server [
| rest /servicesNS/nobody/search/configs/conf-server/ search="sslConfig"
| table splunk_server sslVerifyServerCert sslVerifyServerName serverCert] 
| fillnull value="Not Set" 
| rename sslVerifyServerCert as "Server.conf:SslConfig:sslVerifyServerCert", sslVerifyServerName as "Server.conf:SslConfig:sslVerifyServerName", serverCert as "Server.conf:SslConfig:serverCert" 
| `splunk_digital_certificates_infrastructure_version_filter`
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **splunk_digital_certificates_infrastructure_version_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* none


#### How To Implement
The user running this search is required to have a permission allowing them to dispatch REST requests to indexers (the `dispatch_rest_to_indexers` capability) in some architectures. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
No known at this time.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 50.0 | 50 | 100 | $splunk_server$ may not be properly validating TLS Certificates |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation#Configure_TLS_host_name_validation_for_Splunk-to-Splunk_communication](https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation#Configure_TLS_host_name_validation_for_Splunk-to-Splunk_communication)
* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0602.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0602.html)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_digital_certificates_infrastructure_version.yml) \| *version*: **1**