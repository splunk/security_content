---
title: "Azure Active Directory High Risk Sign-in"
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

The following analytic triggers on a high risk sign-in against Azure Active Directory identified by Azure Identity Protection. Identity Protection monitors sign-in events using heuristics and machine learning to identify potentially malicious events and categorizes them in three categories high, medium and low.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-11
- **Author**: Mauricio Velazco, Splunk
- **ID**: 1ecff169-26d7-4161-9a7b-2ac4c8e61bea


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
 `azuread` body.category=UserRiskEvents body.properties.riskLevel=high 
| rename body.properties.* as * 
|  stats values(userPrincipalName) by _time, ipAddress, activity, riskLevel, riskEventType, additionalInfo 
| `azure_active_directory_high_risk_sign_in_filter`
```

#### Macros
The SPL above uses the following Macros:
* [azuread](https://github.com/splunk/security_content/blob/develop/macros/azuread.yml)

> :information_source:
> **azure_active_directory_high_risk_sign-in_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* body.category
* body.properties.riskLevel
* body.properties.userPrincipalName
* body.properties.ipAddress
* body.properties.activity
* body.properties.riskEventType
* body.properties.additionalInfo


#### How To Implement
You must install the latest version of  Splunk Add-on for Microsoft Cloud Services from  Splunkbase (https://splunkbase.splunk.com/app/3110/#/details). You must be ingesting Azure Active Directory events into your Splunk environment. You must be ingesting Azure Active Directory events in your Splunk environment. Specifically, this analytic leverages the RiskyUsers and UserRiskEvents log category.

#### Known False Positives
Details for the risk calculation algorithm used by Identity Protection are unknown and may be prone to false positives.

#### Associated Analytic story
* [Azure Active Directory Account Takeover](/stories/azure_active_directory_account_takeover)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 60 | 90 | A high risk event was identified by Identify Protection for user $body.properties.userPrincipalName$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray](https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray)
* [https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)
* [https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azuread_highrisk/azure-audit.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azuread_highrisk/azure-audit.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/azure_active_directory_high_risk_sign_in.yml) \| *version*: **1**