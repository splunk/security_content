---
title: "Unusual Number of Remote Endpoint Authentication Events"
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

The following hunting analytic leverages Event ID 4624, `An account was successfully logged on`, to identify an unusual number of remote authentication attempts coming from one source. An endpoint authenticating to a large number of remote endpoints could represent malicious behavior like lateral movement, malware staging, reconnaissance, etc.\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual high number of authentication events. To customize this analytic, users can try different combinations of the `bucket` span time,  the calculation of the `upperBound` field as well as the Outlier calculation. This logic can be used for real time security monitoring as well as threat hunting exercises.\

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-12-01
- **Author**: Mauricio Velazco, Splunk
- **ID**: acb5dc74-5324-11ec-a36d-acde48001122


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

* Reconnaissance


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
 `wineventlog_security` EventCode=4624 Logon_Type=3 Account_Name!="*$" 
| eval Source_Account = mvindex(Account_Name, 1) 
| bucket span=2m _time 
| stats dc(ComputerName) AS unique_targets values(ComputerName) as target_hosts by _time, Source_Network_Address, Source_Account 
| eventstats avg(unique_targets) as comp_avg , stdev(unique_targets) as comp_std by Source_Network_Address, Source_Account 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_targets >10 and unique_targets >= upperBound, 1, 0) 
| `unusual_number_of_remote_endpoint_authentication_events_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that **unusual_number_of_remote_endpoint_authentication_events_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Logon_Type
* Caller_Process_Name
* Security_ID
* Account_Name
* ComputerName


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Event Logs from domain controllers aas well as member servers and workstations. The Advanced Security Audit policy setting `Audit Logon` within `Logon/Logoff` needs to be enabled.

#### Known False Positives
An single endpoint authenticating to a large number of hosts is not common behavior. Possible false positive scenarios include but are not limited to vulnerability scanners, jump servers and missconfigured systems.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/unusual_number_of_remote_endpoint_authentication_events.yml) \| *version*: **1**