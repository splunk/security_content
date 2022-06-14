---
title: "Kerberos Service Ticket Request Using RC4 Encryption"
excerpt: "Steal or Forge Kerberos Tickets
, Golden Ticket
"
categories:
  - Endpoint
last_modified_at: 2022-03-15
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - Golden Ticket
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic leverages Kerberos Event 4769, A Kerberos service ticket was requested, to identify a potential Kerberos Service Ticket request related to a Golden Ticket attack. Adversaries who have obtained the Krbtgt account NTLM password hash may forge a Kerberos Granting Ticket (TGT) to obtain unrestricted access to an Active Directory environment. Armed with a Golden Ticket, attackers can request service tickets to move laterally and execute code on remote systems. Looking for Kerberos Service Ticket requests using the legacy RC4 encryption mechanism could represent the second stage of a Golden Ticket attack. RC4 usage should be rare on a modern network since Windows Vista & Windows Sever 2008 and newer support AES Kerberos encryption.\ Defenders should note that if an attacker does not leverage the NTLM password hash but rather the AES key to create a golden ticket, this detection may be bypassed.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-15
- **Author**: Mauricio Velazco, Splunk
- **ID**: 7d90f334-a482-11ec-908c-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | Golden Ticket | Credential Access |

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
 `wineventlog_security` EventCode=4769 Service_Name="*$" (Ticket_Options=0x40810000 OR Ticket_Options=0x40800000 OR Ticket_Options=0x40810010) Ticket_Encryption_Type=0x17 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, service, service_id, Ticket_Encryption_Type, Ticket_Options 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `kerberos_service_ticket_request_using_rc4_encryption_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

> :information_source:
> **kerberos_service_ticket_request_using_rc4_encryption_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Based on Microsoft documentation, legacy systems or applications will use RC4-HMAC as the default encryption for Kerberos Service Ticket requests. Specifically, systems before Windows Server 2008 and Windows Vista. Newer systems will use AES128 or AES256.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | A Kerberos Service TTicket request with RC4 encryption was requested from $Client_Address$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1558/001/](https://attack.mitre.org/techniques/T1558/001/)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
* [https://adsecurity.org/?p=1515](https://adsecurity.org/?p=1515)
* [https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)
* [https://en.hackndo.com/kerberos-silver-golden-tickets/](https://en.hackndo.com/kerberos-silver-golden-tickets/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.001/impacket/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.001/impacket/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/kerberos_service_ticket_request_using_rc4_encryption.yml) \| *version*: **1**