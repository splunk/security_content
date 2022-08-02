---
title: "Azure AD Authentication Failed During MFA Challenge"
excerpt: "Valid Accounts
, Cloud Accounts
, Multi-Factor Authentication Request Generation
"
categories:
  - Cloud
last_modified_at: 2022-07-14
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Cloud Accounts
  - Multi-Factor Authentication Request Generation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies an authentication attempt event against an Azure AD tenant that fails during the Multi Factor Authentication challenge. This behavior may represent an adversary trying to authenticate with compromised credentials. In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-14
- **Author**: Mauricio Velazco, Splunk
- **ID**: e62c9c2e-bf51-4719-906c-3074618fcc1c


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation | Credential Access |

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
 `azuread` body.category=SignInLogs body.properties.status.errorCode=500121 
| rename body.properties.* as * 
| stats values(userPrincipalName) by _time, ipAddress, status.additionalDetails, appDisplayName, userAgent 
| `azure_ad_authentication_failed_during_mfa_challenge_filter`
```

#### Macros
The SPL above uses the following Macros:
* [azuread](https://github.com/splunk/security_content/blob/develop/macros/azuread.yml)

> :information_source:
> **azure_ad_authentication_failed_during_mfa_challenge_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* body.category
* body.properties.status.errorCode
* body.properties.userPrincipalName
* body.properties.ipAddress
* body.properties.status.additionalDetails
* body.properties.appDisplayName
* body.properties.userAgent


#### How To Implement
You must install the latest version of  Splunk Add-on for Microsoft Cloud Services from  Splunkbase(https://splunkbase.splunk.com/app/3110/#/details). You must be ingesting Azure Active Directory events into your Splunk environment. You must be ingesting Azure Active Directory events in your Splunk environment. Specifically, this analytic leverages the RiskyUsers and UserRiskEvents log category.

#### Known False Positives
Legitimate users may miss to reply the MFA challenge within the time window or deny it by mistake.

#### Associated Analytic story
* [Azure Active Directory Account Takeover](/stories/azure_active_directory_account_takeover)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 60 | 90 | User $body.properties.userPrincipalName$ failed to pass MFA challenge |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1621/](https://attack.mitre.org/techniques/T1621/)
* [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)
* [https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/azuread/azure-audit.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/azuread/azure-audit.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/azure_ad_authentication_failed_during_mfa_challenge.yml) \| *version*: **1**