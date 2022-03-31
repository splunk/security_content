---
title: "Kerberos Pre-Authentication Flag Disabled in UserAccountControl"
excerpt: "Steal or Forge Kerberos Tickets
, AS-REP Roasting
"
categories:
  - Endpoint
last_modified_at: 2022-02-22
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - AS-REP Roasting
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic leverages Windows Security Event 4738, `A user account was changed`, to identify a change performed on a domain user object that disables Kerberos Pre-Authentication. Disabling the Pre Authentication flag in the UserAccountControl property allows an adversary to easily perform a brute force attack against the user's password offline leveraging the ASP REP Roasting technique. Red Teams and adversaries alike who have obtained privileges in an Active Directory network may use this technique as a backdoor or a way to escalate privileges.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-02-22
- **Author**: Mauricio Velazco, Splunk
- **ID**: 0cb847ee-9423-11ec-b2df-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | Credential Access |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
 `wineventlog_security` EventCode=4738 MSADChangedAttributes="*Don't Require Preauth' - Enabled*" 
| table EventCode, Account_Name, Security_ID, MSADChangedAttributes 
| `kerberos_pre_authentication_flag_disabled_in_useraccountcontrol_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that **kerberos_pre-authentication_flag_disabled_in_useraccountcontrol_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Account_Name
* Security_ID
* MSADChangedAttributes


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller events. The Advanced Security Audit policy setting `User Account Management` within `Account Management` needs to be enabled.

#### Known False Positives
Unknown.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 50 | 90 | Kerberos Pre Authentication was Disabled for $Account_Name$ |


#### Reference

* [https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)
* [https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/](https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powershell/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powershell/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/kerberos_pre-authentication_flag_disabled_in_useraccountcontrol.yml) \| *version*: **1**