---
title: "PetitPotam Network Share Access Request"
excerpt: "Forced Authentication
"
categories:
  - Endpoint
last_modified_at: 2021-08-31
toc: true
toc_label: ""
tags:
  - Forced Authentication
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-36942
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes Windows Event Code 5145, "A network share object was checked to see whether client can be granted desired access". During our research into PetitPotam, CVE-2021-36942, we identified the ocurrence of this event on the target host with specific values. \
To enable 5145 events via Group Policy - Computer Configuration->Polices->Windows Settings->Security Settings->Advanced Audit Policy Configuration. Expand this node, go to Object Access (Audit Polices->Object Access), then select the Setting Audit Detailed File Share Audit \
It is possible this is not enabled by default and may need to be reviewed and enabled. \
During triage, review parallel security events to identify further suspicious activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-08-31
- **Author**: Michael Haag, Mauricio Velazco, Splunk
- **ID**: 95b8061a-0a67-11ec-85ec-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1187](https://attack.mitre.org/techniques/T1187/) | Forced Authentication | Credential Access |

#### Search

```
`wineventlog_security` Account_Name="ANONYMOUS LOGON" EventCode=5145 Relative_Target_Name=lsarpc 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Security_ID, Share_Name, Source_Address, Accesses, Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `petitpotam_network_share_access_request_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `petitpotam_network_share_access_request_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* Security_ID
* Share_Name
* Source_Address
* Accesses
* Message


#### How To Implement
Windows Event Code 5145 is required to utilize this analytic and it may not be enabled in most environments.

#### Known False Positives
False positives have been limited when the Anonymous Logon is used for Account Name.

#### Associated Analytic story
* [PetitPotam NTLM Relay on Active Directory Certificate Services](/stories/petitpotam_ntlm_relay_on_active_directory_certificate_services)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | A remote host is enumerating a $dest$ to identify permissions. This is a precursor event to CVE-2021-36942, PetitPotam. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-36942](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) | Windows LSA Spoofing Vulnerability | 5.0 |



#### Reference

* [https://attack.mitre.org/techniques/T1187/](https://attack.mitre.org/techniques/T1187/)
* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1187/petitpotam/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1187/petitpotam/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/petitpotam_network_share_access_request.yml) \| *version*: **1**