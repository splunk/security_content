---
title: "Azure AD Unusual Number of Failed Authentications From Ip"
excerpt: "Brute Force
, Password Spraying
"
categories:
  - Cloud
last_modified_at: 2022-07-11
toc: true
toc_label: ""
tags:
  - Brute Force
  - Password Spraying
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies one source Ip failing to authenticate with multiple valid users. This behavior could represent an adversary performing a Password Spraying attack against an Azure Active Directory tenant to obtain initial access or elevate privileges. Error Code 50126 represents an invalid password.\
The detection calculates the standard deviation for source Ip and leverages the 3-sigma statistical rule to identify an unusual number of failed authentication attempts. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field. This logic can be used for real time security monitoring as well as threat hunting exercises.\
While looking for anomalies using statistical methods like the standard deviation can have benefits, we also recommend using threshold-based detections to complement coverage. A similar analytic following the threshold model is `Azure AD Multiple Users Failing To Authenticate From Ip`.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-11
- **Author**: Mauricio Velazco, Splunk
- **ID**: 3d8d3a36-93b8-42d7-8d91-c5f24cec223d


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Credential Access |

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


</div>
</details>

#### Search 

```
 `azuread` body.properties.status.errorCode= 50126 body.category= SignInLogs body.properties.authenticationDetails{}.succeeded= false 
| rename body.properties.* as * 
| bucket span=5m _time 
| stats  dc(userPrincipalName) AS unique_accounts values(userPrincipalName) as tried_accounts by _time, ipAddress 
| eventstats  avg(unique_accounts) as ip_avg , stdev(unique_accounts) as ip_std by ipAddress 
| eval  upperBound=(ip_avg+ip_std*3) 
| eval  isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0) 
| `azure_ad_unusual_number_of_failed_authentications_from_ip_filter`
```

#### Macros
The SPL above uses the following Macros:
* [azuread](https://github.com/splunk/security_content/blob/develop/macros/azuread.yml)

> :information_source:
> **azure_ad_unusual_number_of_failed_authentications_from_ip_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* body.properties.status.errorCode
* body.category
* body.properties.authenticationDetails
* body.properties.userPrincipalName
* body.properties.ipAddress


#### How To Implement
You must install the latest version of  Splunk Add-on for Microsoft Cloud Services from  Splunkbase(https://splunkbase.splunk.com/app/3110/#/details). You must be ingesting Azure Active Directory events into your Splunk environment. You must be ingesting Azure Active Directory events in your Splunk environment. Specifically, this analytic leverages the SignInLogs log category.

#### Known False Positives
A source Ip failing to authenticate with multiple users is not a common for legitimate behavior.

#### Associated Analytic story
* [Azure Active Directory Account Takeover](/stories/azure_active_directory_account_takeover)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 60 | 90 | Possible Password Spraying attack against Azure AD from source ip $body.properties.ipAddress$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray](https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray)
* [https://www.cisa.gov/uscert/ncas/alerts/aa21-008a](https://www.cisa.gov/uscert/ncas/alerts/aa21-008a)
* [https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azuread/azure-audit.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azuread/azure-audit.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/azure_ad_unusual_number_of_failed_authentications_from_ip.yml) \| *version*: **1**