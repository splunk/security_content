---
title: "O365 Bypass MFA via Trusted IP"
excerpt: "Disable or Modify Cloud Firewall
, Impair Defenses
"
categories:
  - Cloud
last_modified_at: 2022-02-03
toc: true
toc_label: ""
tags:
  - Disable or Modify Cloud Firewall
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects newly added IP addresses/CIDR blocks to the list of MFA Trusted IPs to bypass multi factor authentication. Attackers are often known to use this technique so that they can bypass the MFA system.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-02-03
- **Author**: Bhavin Patel, Splunk
- **ID**: c783dd98-c703-4252-9e8a-f19d9f66949e


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Disable or Modify Cloud Firewall | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```
`o365_management_activity` Operation="Set Company Information." ModifiedProperties{}.Name=StrongAuthenticationPolicy 
| rex max_match=100 field=ModifiedProperties{}.NewValue "(?<ip_addresses_new_added>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})" 
| rex max_match=100 field=ModifiedProperties{}.OldValue "(?<ip_addresses_old>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})" 
| eval ip_addresses_old=if(isnotnull(ip_addresses_old),ip_addresses_old,"0") 
| mvexpand ip_addresses_new_added 
| where isnull(mvfind(ip_addresses_old,ip_addresses_new_added)) 
|stats count min(_time) as firstTime max(_time) as lastTime values(ip_addresses_old) as ip_addresses_old by user ip_addresses_new_added Operation Workload vendor_account status user_id action 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `o365_bypass_mfa_via_trusted_ip_filter`
```

#### Macros
The SPL above uses the following Macros:
* [o365_management_activity](https://github.com/splunk/security_content/blob/develop/macros/o365_management_activity.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `o365_bypass_mfa_via_trusted_ip_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* signature
* ModifiedProperties{}.Name
* ModifiedProperties{}.NewValue
* ModifiedProperties{}.OldValue
* user
* vendor_account
* status
* user_id
* action


#### How To Implement
You must install Splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Known False Positives
Unless it is a special case, it is uncommon to continually update Trusted IPs to MFA configuration.

#### Associated Analytic story
* [Office 365 Detections](/stories/office_365_detections)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user_id$ has added new IP addresses $ip_addresses_new_added$ to a list of trusted IPs to bypass MFA |




#### Reference

* [https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf](https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf)
* [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/o365_bypass_mfa_via_trusted_ip/o365_bypass_mfa_via_trusted_ip.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/o365_bypass_mfa_via_trusted_ip/o365_bypass_mfa_via_trusted_ip.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_bypass_mfa_via_trusted_ip.yml) \| *version*: **2**