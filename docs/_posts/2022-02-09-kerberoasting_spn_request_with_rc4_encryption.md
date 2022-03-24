---
title: "Kerberoasting spn request with RC4 encryption"
excerpt: "Steal or Forge Kerberos Tickets
, Kerberoasting
"
categories:
  - Endpoint
last_modified_at: 2022-02-09
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - Kerberoasting
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic leverages Kerberos Event 4769, A Kerberos service ticket was requested, to identify a potential kerberoasting attack against Active Directory networks. Kerberoasting allows an adversary to request kerberos tickets for domain accounts typically used as service accounts and attempt to crack them offline allowing them to obtain privileged access to the domain. This analytic looks for a specific combination of the Ticket_Options field based on common kerberoasting tools. Defenders should be aware that it may be possible for a Kerberoast attack to use different Ticket_Options.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-02-09
- **Author**: Jose Hernandez, Patrick Bareiss, Mauricio Velazco, Splunk
- **ID**: 5cc67381-44fa-4111-8a37-7a230943f027


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

#### Search

```
`wineventlog_security` EventCode=4769 Service_Name!="*$" (Ticket_Options=0x40810000 OR Ticket_Options=0x40800000 OR Ticket_Options=0x40810010) Ticket_Encryption_Type=0x17 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, service, service_id, Ticket_Encryption_Type, Ticket_Options 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `kerberoasting_spn_request_with_rc4_encryption_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `kerberoasting_spn_request_with_rc4_encryption_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Ticket_Options
* Ticket_Encryption_Type
* dest
* service
* service_id


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
Older systems that support kerberos RC4 by default like NetApp may generate false positives. Filter as needed

#### Associated Analytic story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | Potential kerberoasting attack via service principal name requests detected on $dest$ |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1208/T1208.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1208/T1208.md)
* [https://www.trimarcsecurity.com/post/trimarcresearch-detecting-kerberoasting-activity](https://www.trimarcsecurity.com/post/trimarcresearch-detecting-kerberoasting-activity)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/rubeus/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/rubeus/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/kerberoasting_spn_request_with_rc4_encryption.yml) \| *version*: **4**