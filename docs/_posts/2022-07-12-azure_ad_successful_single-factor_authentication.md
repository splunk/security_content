---
title: "Azure AD Successful Single-Factor Authentication"
excerpt: "Security Account Manager
"
categories:
  - Cloud
last_modified_at: 2022-07-12
toc: true
toc_label: ""
tags:
  - Security Account Manager
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a successful authentication event against Azure Active Directory for an account without Multi-Factor Authentication enabled. This could be evidence of a missconfiguration, a policy violation or an account take over attempt that should be investigated

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-12
- **Author**: Mauricio Velazco, Splunk
- **ID**: a560e7f6-1711-4353-885b-40be53101fcd


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |

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
 `azuread`  body.category=SignInLogs body.properties.authenticationRequirement=singleFactorAuthentication body.properties.authenticationDetails{}.succeeded=true 
| rename body.properties.* as * 
|  stats values(userPrincipalName) by _time, ipAddress, appDisplayName, authenticationRequirement 
| `azure_ad_successful_single_factor_authentication_filter`
```

#### Macros
The SPL above uses the following Macros:
* [azuread](https://github.com/splunk/security_content/blob/develop/macros/azuread.yml)

> :information_source:
> **azure_ad_successful_single-factor_authentication_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* body.category
* body.properties.authenticationRequirement
* body.properties.authenticationDetails
* body.properties.userPrincipalName
* body.properties.ipAddress
* body.properties.appDisplayName


#### How To Implement
You must install the latest version of  Splunk Add-on for Microsoft Cloud Services from  Splunkbase(https://splunkbase.splunk.com/app/3110/#/details). You must be ingesting Azure Active Directory events into your Splunk environment. You must be ingesting Azure Active Directory events in your Splunk environment. Specifically, this analytic leverages the SignInLogs log category.

#### Known False Positives
Although not recommended, certain users may be required without multi-factor authentication. Filter as needed

#### Associated Analytic story
* [Azure Active Directory Account Takeover](/stories/azure_active_directory_account_takeover)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 50.0 | 50 | 100 | Successful authentication for user $body.properties.userPrincipalName$ without MFA |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)
* [https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks*](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks*)
* [https://www.forbes.com/sites/daveywinder/2020/07/08/new-dark-web-audit-reveals-15-billion-stolen-logins-from-100000-breaches-passwords-hackers-cybercrime/?sh=69927b2a180f](https://www.forbes.com/sites/daveywinder/2020/07/08/new-dark-web-audit-reveals-15-billion-stolen-logins-from-100000-breaches-passwords-hackers-cybercrime/?sh=69927b2a180f)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azuread/azure-audit.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azuread/azure-audit.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/azure_ad_successful_single_factor_authentication.yml) \| *version*: **1**