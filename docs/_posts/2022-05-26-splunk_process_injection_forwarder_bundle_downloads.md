---
title: "Splunk Process Injection Forwarder Bundle Downloads"
excerpt: "Process Injection
"
categories:
  - Application
last_modified_at: 2022-05-26
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32157
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

On June 14th, 2022, Splunk released a security advisory relating to the authentication that happens between Universal Forwarders and Deployment Servers. In some circumstances, an unauthenticated client can download forwarder bundles from the Deployment Server. This hunting search pulls a full list of forwarder bundle downloads where the peer column is the forwarder, the host column is the Deployment Server, and then you have a list of the apps downloaded and the serverclasses in which the peer is a member of. You should look for apps or clients that you do not recognize as being part of your environment.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-26
- **Author**: Lou Stella, Splunk
- **ID**: 8ea57d78-1aac-45d2-a913-0cd603fb6e9e


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

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
| [CVE-2022-32157](https://nvd.nist.gov/vuln/detail/CVE-2022-32157) | Splunk Enterprise deployment servers in versions before 9.0 allow unauthenticated downloading of forwarder bundles. Remediation requires you to update the deployment server to version 9.0 and Configure authentication for deployment servers and clients (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/ConfigDSDCAuthEnhancements#Configure_authentication_for_deployment_servers_and_clients). Once enabled, deployment servers can manage only Universal Forwarder versions 9.0 and higher. Though the vulnerability does not directly affect Universal Forwarders, remediation requires updating all Universal Forwarders that the deployment server manages to version 9.0 or higher prior to enabling the remediation. | 5.0 |



</div>
</details>

#### Search 

```
`splunkd` component="PackageDownloadRestHandler" 
| stats values(app) values(serverclass) by peer, host 
| `splunk_process_injection_forwarder_bundle_downloads_filter`
```

#### Macros
The SPL above uses the following Macros:
* [splunkd](https://github.com/splunk/security_content/blob/develop/macros/splunkd.yml)

> :information_source:
> **splunk_process_injection_forwarder_bundle_downloads_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* component
* app
* serverclass
* peer
* host


#### How To Implement
This hunting search uses native logs produced when a deployment server is within your environment. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
None at this time.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | $peer$ downloaded apps from $host$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0607.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0607.html)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/splunk_ds/splunkd.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/splunk_ds/splunkd.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_process_injection_forwarder_bundle_downloads.yml) \| *version*: **1**