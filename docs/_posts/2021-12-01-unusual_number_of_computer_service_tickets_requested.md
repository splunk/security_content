---
title: "Unusual Number of Computer Service Tickets Requested"
excerpt: "Valid Accounts
"
categories:
  - Endpoint
last_modified_at: 2021-12-01
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic leverages Event ID 4769, `A Kerberos service ticket was requested`, to identify an unusual number of computer service ticket requests from one source. When a domain joined endpoint connects to a remote endpoint, it first will request a Kerberos Ticket with the computer name as the Service Name. An endpoint requesting a large number of computer service tickets for different endpoints could represent malicious behavior like lateral movement, malware staging, reconnaissance, etc.\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number of service requests. To customize this analytic, users can try different combinations of the `bucket` span time,  the calculation of the `upperBound` field as well as the Outlier calculation. This logic can be used for real time security monitoring as well as threat hunting exercises.\

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-12-01
- **Author**: Mauricio Velazco, Splunk
- **ID**: ac3b81c0-52f4-11ec-ac44-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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
 `wineventlog_security` EventCode=4769 Service_Name="*$" Account_Name!="*$*" 
| bucket span=2m _time 
| stats dc(Service_Name) AS unique_targets values(Service_Name) as host_targets by _time, Client_Address, Account_Name 
| eventstats avg(unique_targets) as comp_avg , stdev(unique_targets) as comp_std by Client_Address, Account_Name 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_targets >10 and unique_targets >= upperBound, 1, 0) 
| `unusual_number_of_computer_service_tickets_requested_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that **unusual_number_of_computer_service_tickets_requested_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
An single endpoint requesting a large number of computer service tickets is not common behavior. Possible false positive scenarios include but are not limited to vulnerability scanners, administration systeams and missconfigured systems.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 |  |


#### Reference

* [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/unusual_number_of_computer_service_tickets_requested.yml) \| *version*: **1**