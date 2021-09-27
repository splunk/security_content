---
title: "Multiple Users Attempting To Authenticate Using Explicit Credentials"
excerpt: "Password Spraying"
categories:
  - Endpoint
last_modified_at: 2021-04-13
toc: true
tags:
  - Anomaly
  - T1110.003
  - Password Spraying
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a source user failing to authenticate with multiple users using explicit credentials on a host. This behavior could represent an adversary performing a Password Spraying attack against an Active Directory environment to obtain initial access or elevate privileges. Event 4648 is generated when a process attempts an account logon by explicitly specifying that accounts credentials. This event generates on domain controllers, member servers, and workstations.\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number of users. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field. This logic can be used for real time security monitoring as well as threat hunting exercises.\
This detection will trigger on the potenfially malicious host, perhaps controlled via a trojan or operated by an insider threat, from where a password spraying attack is being executed.\
The analytics returned fields allow analysts to investigate the event further by providing fields like source account, attempted user accounts and the endpoint were the behavior was identified.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-13
- **Author**: Mauricio Velazco, Splunk
- **ID**: e61918fa-9ca4-11eb-836c-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Credential Access |


#### Search

```
 `wineventlog_security` EventCode=4648 
| bucket span=2m _time 
| eval Source_Account = mvindex(Account_Name, 0) 
| eval Destination_Account = mvindex(Account_Name, 1) 
| search Source_Account != "*$" Source_Account !="-" Destination_Account !="*$" 
| stats dc(Destination_Account) AS unique_accounts values(Destination_Account) as tried_account by _time, ComputerName, Source_Account 
| eventstats avg(unique_accounts) as comp_avg , stdev(unique_accounts) as comp_std by ComputerName 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0) 
| search isOutlier=1 
| `multiple_users_attempting_to_authenticate_using_explicit_credentials_filter` 
```

#### Associated Analytic Story
* [Active Directory Password Spraying](/stories/active_directory_password_spraying)


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Event Logs from domain controllers as well as member servers and workstations. The Advanced Security Audit policy setting `Audit Logon` within `Logon/Logoff` needs to be enabled.

#### Required field
* _time
* EventCode
* Security_ID
* Account_Name
* ComputerName


#### Kill Chain Phase
* Exploitation


#### Known False Positives
A source user failing attempting to authenticate multiple users on a host is not a common behavior for regular systems. Some applications, however, may exhibit this behavior in which case sets of users hosts can be added to an allow list. Possible false positive scenarios include systems where several users connect to like Mail servers, identity providers, remote desktop services, Citrix, etc.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Potential password spraying attack from $ComputerName$ |



#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_explicit_credential_spray/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_explicit_credential_spray/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/multiple_users_attempting_to_authenticate_using_explicit_credentials.yml) \| *version*: **1**