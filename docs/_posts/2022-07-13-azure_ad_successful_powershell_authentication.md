---
title: "Azure AD Successful PowerShell Authentication"
excerpt: "Valid Accounts
, Cloud Accounts
"
categories:
  - Cloud
last_modified_at: 2022-07-13
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Cloud Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a successful authentication event against an Azure AD tenant using PowerShell commandlets. This behavior is not common for regular, non administrative users. After compromising an account in Azure AD, attackers and red teams  alike will perform enumeration and discovery techniques. One method of executing these techniques is leveraging the native PowerShell modules.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-13
- **Author**: Mauricio Velazco, Splunk
- **ID**: 62f10052-d7b3-4e48-b57b-56f8e3ac7ceb


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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
 `azuread` body.category=SignInLogs body.properties.authenticationDetails{}.succeeded=true body.properties.appDisplayName="Azure Active Directory PowerShell" 
| rename body.properties.* as * 
|  stats values(userPrincipalName) by _time, ipAddress, appDisplayName, userAgent 
| `azure_ad_successful_powershell_authentication_filter`
```

#### Macros
The SPL above uses the following Macros:
* [azuread](https://github.com/splunk/security_content/blob/develop/macros/azuread.yml)

> :information_source:
> **azure_ad_successful_powershell_authentication_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* body.properties.appDisplayName
* body.category
* body.properties.userPrincipalName
* body.properties.ipAddress
* body.properties.appDisplayName
* body.properties.userAgent


#### How To Implement
You must install the latest version of  Splunk Add-on for Microsoft Cloud Services from  Splunkbase(https://splunkbase.splunk.com/app/3110/#/details). You must be ingesting Azure Active Directory events into your Splunk environment. You must be ingesting Azure Active Directory events in your Splunk environment. Specifically, this analytic leverages the SignInLogs log category.

#### Known False Positives
Administrative users will likely use PowerShell commandlets to troubleshoot and maintain the environment. Filter as needed.

#### Associated Analytic story
* [Azure Active Directory Account Takeover](/stories/azure_active_directory_account_takeover)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 60 | 90 | Successful authentication for user $body.properties.userPrincipalName$ using PowerShell. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)
* [https://docs.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0](https://docs.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0)
* [https://securitycafe.ro/2022/04/29/pentesting-azure-recon-techniques/](https://securitycafe.ro/2022/04/29/pentesting-azure-recon-techniques/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azuread_pws/azure-audit.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azuread_pws/azure-audit.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/azure_ad_successful_powershell_authentication.yml) \| *version*: **1**