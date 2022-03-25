---
title: "PetitPotam Suspicious Kerberos TGT Request"
excerpt: "OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2021-08-31
toc: true
toc_label: ""
tags:
  - OS Credential Dumping
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-36942
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifes Event Code 4768, A `Kerberos authentication ticket (TGT) was requested`, successfull occurs. This behavior has been identified to assist with detecting PetitPotam, CVE-2021-36942. Once an attacer obtains a computer certificate by abusing Active Directory Certificate Services in combination with PetitPotam, the next step would be to leverage the certificate for malicious purposes. One way of doing this is to request a Kerberos Ticket Granting Ticket using a tool like Rubeus. This request will generate a 4768 event with some unusual fields depending on the environment. This analytic will require tuning, we recommend filtering Account_Name to Domain Controllers for your environment.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-08-31
- **Author**: Michael Haag, Mauricio Velazco, Splunk
- **ID**: e3ef244e-0a67-11ec-abf2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`wineventlog_security` EventCode=4768 Client_Address!="::1" Certificate_Thumbprint!="" Account_Name=*$ 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Account_Name, Client_Address, action, Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `petitpotam_suspicious_kerberos_tgt_request_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `petitpotam_suspicious_kerberos_tgt_request_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* Account_Name
* Client_Address
* action
* Message


#### How To Implement
The following analytic requires Event Code 4768. Ensure that it is logging no Domain Controllers and appearing in Splunk.

#### Known False Positives
False positives are possible if the environment is using certificates for authentication.

#### Associated Analytic story
* [PetitPotam NTLM Relay on Active Directory Certificate Services](/stories/petitpotam_ntlm_relay_on_active_directory_certificate_services)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | A Kerberos TGT was requested in a non-standard manner against $dest$, potentially related to CVE-2021-36942, PetitPotam. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-36942](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) | Windows LSA Spoofing Vulnerability | 5.0 |



#### Reference

* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4768](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4768)
* [https://isc.sans.edu/forums/diary/Active+Directory+Certificate+Services+ADCS+PKI+domain+admin+vulnerability/27668/](https://isc.sans.edu/forums/diary/Active+Directory+Certificate+Services+ADCS+PKI+domain+admin+vulnerability/27668/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1187/petitpotam/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1187/petitpotam/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/petitpotam_suspicious_kerberos_tgt_request.yml) \| *version*: **1**