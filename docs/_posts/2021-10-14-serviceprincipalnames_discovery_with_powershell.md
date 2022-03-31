---
title: "ServicePrincipalNames Discovery with PowerShell"
excerpt: "Kerberoasting
"
categories:
  - Endpoint
last_modified_at: 2021-10-14
toc: true
toc_label: ""
tags:
  - Kerberoasting
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `powershell.exe` usage, using Script Block Logging EventCode 4104, related to querying the domain for Service Principle Names. typically, this is a precursor activity related to kerberoasting or the silver ticket attack. \
What is a ServicePrincipleName? \
A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.\
The following analytic identifies the use of KerberosRequestorSecurityToken class within the script block. Using .NET System.IdentityModel.Tokens.KerberosRequestorSecurityToken class in PowerShell is the equivelant of using setspn.exe. \
During triage, review parallel processes for further suspicious activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-10-14
- **Author**: Michael Haag, Splunk
- **ID**: 13243068-2d38-11ec-8908-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

#### Search

```
`powershell` EventCode=4104 Message="*KerberosRequestorSecurityToken*" 
| stats count min(_time) as firstTime max(_time) as lastTime by Message OpCode ComputerName User EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `serviceprincipalnames_discovery_with_powershell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `serviceprincipalnames_discovery_with_powershell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
False positives should be limited, however filter as needed.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to identify service principle names. |




#### Reference

* [https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)
* [https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://strontic.github.io/xcyclopedia/library/setspn.exe-5C184D581524245DAD7A0A02B51FD2C2.html](https://strontic.github.io/xcyclopedia/library/setspn.exe-5C184D581524245DAD7A0A02B51FD2C2.html)
* [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)
* [https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spn-setspn-syntax.aspx](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spn-setspn-syntax.aspx)
* [https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [https://blog.zsec.uk/paving-2-da-wholeset/](https://blog.zsec.uk/paving-2-da-wholeset/)
* [https://msitpros.com/?p=3113](https://msitpros.com/?p=3113)
* [https://adsecurity.org/?p=3466](https://adsecurity.org/?p=3466)
* [https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.](https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.)
* [https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
* [https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
* [https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/atomic_red_team/windows-powershell_kerberos.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/atomic_red_team/windows-powershell_kerberos.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/serviceprincipalnames_discovery_with_powershell.yml) \| *version*: **1**