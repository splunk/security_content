---
title: "Splunk Protocol Impersonation Weak Encryption Configuration"
excerpt: "Protocol Impersonation
"
categories:
  - Application
last_modified_at: 2022-05-25
toc: true
toc_label: ""
tags:
  - Protocol Impersonation
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32151
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

On June 14th, 2022, Splunk released a security advisory relating to TLS validation occuring within the httplib and urllib python libraries shipped with Splunk. In addition to upgrading to Splunk Enterprise 9.0 or later, several configuration settings need to be set. This search will check those configurations on the search head it is run from as well as its search peers. In addition to these settings, the PYTHONHTTPSVERIFY setting in $SPLUNK_HOME/etc/splunk-launch.conf needs to be enabled as well. Other components such as additional search heads or anything this rest command cannot be distributed to will need to be manually checked.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-25
- **Author**: Lou Stella, Splunk
- **ID**: 900892bf-70a9-4787-8c99-546dd98ce461


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1001.003](https://attack.mitre.org/techniques/T1001/003/) | Protocol Impersonation | Command And Control |

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

| rest /services/server/info 
| table splunk_server version server_roles 
| join splunk_server [
| rest /servicesNS/nobody/search/configs/conf-server/ search="PythonSslClientConfig" 
| table splunk_server sslVerifyServerCert sslVerifyServerName] 
| join splunk_server [
| rest /servicesNS/nobody/search/configs/conf-web/settings 
|  table splunk_server serverCert sslVersions] 
| rename sslVerifyServerCert as "Server.conf:PythonSSLClientConfig:sslVerifyServerCert", sslVerifyServerName as "Server.conf:PythonSSLClientConfig:sslVerifyServerName", serverCert as "Web.conf:Settings:serverCert", sslVersions as "Web.conf:Settings:sslVersions" 
| `splunk_protocol_impersonation_weak_encryption_configuration_filter`
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **splunk_protocol_impersonation_weak_encryption_configuration_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* none


#### How To Implement
The user running this search is required to have a permission allowing them to dispatch REST requests to indexers (The `dispatch_rest_to_indexers` capability). Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
While all of the settings on each device returned by this search may appear to be hardened, you will still need to verify the value of PYTHONHTTPSVERIFY in $SPLUNK_HOME/etc/splunk-launch.conf on each device in order to harden the python configuration.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 50.0 | 50 | 100 | $splunk_server$ may not be properly validating TLS Certificates |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation](https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation)
* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0601.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0601.html)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_protocol_impersonation_weak_encryption_configuration.yml) \| *version*: **1**