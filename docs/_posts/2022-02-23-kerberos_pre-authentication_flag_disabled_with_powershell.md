---
title: "Kerberos Pre-Authentication Flag Disabled with PowerShell"
excerpt: "Steal or Forge Kerberos Tickets
, AS-REP Roasting
"
categories:
  - Endpoint
last_modified_at: 2022-02-23
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

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Set-ADAccountControl` commandlet with specific parameters. `Set-ADAccountControl` is part of the Active Directory PowerShell module used to manage Windows Active Directory networks. As the name suggests, `Set-ADAccountControl` is used to modify User Account Control values for an Active Directory domain account. With the appropiate parameters, Set-ADAccountControl allows adversaries to disable Kerberos Pre-Authentication for an account to to easily perform a brute force attack against the user's password offline leveraging the ASP REP Roasting technique. Red Teams and adversaries alike who have obtained privileges in an Active Directory network may use this technique as a backdoor or a way to escalate privileges.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-02-23
- **Author**: Mauricio Velazco, Splunk
- **ID**: 59b51620-94c9-11ec-b3d5-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | Credential Access |

#### Search

```
 `powershell` EventCode=4104 (Message = "*Set-ADAccountControl*" AND Message="*DoesNotRequirePreAuth:$true*") 
| stats count min(_time)  as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `kerberos_pre_authentication_flag_disabled_with_powershell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `kerberos_pre-authentication_flag_disabled_with_powershell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Although unlikely, Administrators may need to set this flag for legitimate purposes.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 50 | 90 | Kerberos Pre Authentication was Disabled using PowerShell on $dest$ |




#### Reference

* [https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)
* [https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/](https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powershell/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powershell/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/kerberos_pre-authentication_flag_disabled_with_powershell.yml) \| *version*: **1**