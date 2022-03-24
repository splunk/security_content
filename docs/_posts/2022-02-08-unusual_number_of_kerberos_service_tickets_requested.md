---
title: "Unusual Number of Kerberos Service Tickets Requested"
excerpt: "Steal or Forge Kerberos Tickets
, Kerberoasting
"
categories:
  - Endpoint
last_modified_at: 2022-02-08
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

The following hunting analytic leverages Kerberos Event 4769, A Kerberos service ticket was requested, to identify a potential kerberoasting attack against Active Directory networks. Kerberoasting allows an adversary to request kerberos tickets for domain accounts typically used as service accounts and attempt to crack them offline allowing them to obtain privileged access to the domain.\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number service ticket requests. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-02-08
- **Author**: Mauricio Velazco, Splunk
- **ID**: eb3e6702-8936-11ec-98fe-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

#### Search

```
 `wineventlog_security` EventCode=4769 Service_Name!="*$" Ticket_Encryption_Type=0x17 
| bucket span=2m _time 
| stats dc(Service_Name) AS unique_services values(Service_Name) as requested_services by _time, Client_Address 
| eventstats avg(unique_services) as comp_avg , stdev(unique_services) as comp_std by Client_Address 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_services > 2 and unique_services >= upperBound, 1, 0) 
| search isOutlier=1 
| `unusual_number_of_kerberos_service_tickets_requested_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `unusual_number_of_kerberos_service_tickets_requested_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Ticket_Options
* Ticket_Encryption_Type
* dest
* Service_Name
* service_id
* Client_Address


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
An single endpoint requesting a large number of kerberos service tickets is not common behavior. Possible false positive scenarios include but are not limited to vulnerability scanners, administration systems and missconfigured systems.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | tbd |




#### Reference

* [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/rubeus/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/rubeus/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/unusual_number_of_kerberos_service_tickets_requested.yml) \| *version*: **1**