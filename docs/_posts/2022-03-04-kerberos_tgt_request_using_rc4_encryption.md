---
title: "Kerberos TGT Request Using RC4 Encryption"
excerpt: "Use Alternate Authentication Material
"
categories:
  - Endpoint
last_modified_at: 2022-03-04
toc: true
toc_label: ""
tags:
  - Use Alternate Authentication Material
  - Defense Evasion
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic leverages Event 4768, A Kerberos authentication ticket (TGT) was requested, to identify a TGT request with encryption type 0x17, or RC4-HMAC. This encryption type is no longer utilized by newer systems and could represent evidence of an OverPass The Hash attack. Similar to Pass The Hash, OverPass The Hash is a form of credential theft that allows adversaries to move laterally or consume resources in a target network. Leveraging this attack, an adversary who has stolen the NTLM hash of a valid domain account is able to authenticate to the Kerberos Distribution Center(KDC) on behalf of the legitimate account and obtain a Kerberos TGT ticket. Depending on the privileges of the compromised account, this ticket may be used to obtain unauthorized access to systems and other network resources.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-04
- **Author**: Mauricio Velazco, Splunk
- **ID**: 18916468-9c04-11ec-bdc6-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

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
 `wineventlog_security` EventCode=4768 Ticket_Encryption_Type=0x17 Account_Name!=*$ 
| `kerberos_tgt_request_using_rc4_encryption_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

> :information_source:
> **kerberos_tgt_request_using_rc4_encryption_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Ticket_Encryption_Type
* Account_Name
* Client_Address


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
Based on Microsoft documentation, legacy systems or applications will use RC4-HMAC as the default encryption for TGT requests. Specifically, systems before Windows Server 2008 and Windows Vista. Newer systems will use AES128 or AES256.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | A Kerberos TGT request with RC4 encryption was requested for $Account_Name$ from $Client_Address$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/](https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/)
* [https://www.thehacker.recipes/ad/movement/kerberos/ptk](https://www.thehacker.recipes/ad/movement/kerberos/ptk)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/impacket/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/impacket/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/kerberos_tgt_request_using_rc4_encryption.yml) \| *version*: **1**