---
title: "Detect Computer Changed with Anonymous Account"
excerpt: "Exploitation of Remote Services
"
categories:
  - Endpoint
last_modified_at: 2020-09-18
toc: true
toc_label: ""
tags:
  - Exploitation of Remote Services
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2020-1472
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for Event Code 4742 (Computer Change) or EventCode 4624 (An account was successfully logged on) with an anonymous account.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-09-18
- **Author**: Rod Soto, Jose Hernandez, Splunk
- **ID**: 1400624a-d42d-484d-8843-e6753e6e3645


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services | Lateral Movement |

#### Search

```
`wineventlog_security` EventCode=4624 OR EventCode=4742 TargetUserName="ANONYMOUS LOGON" LogonType=3 
| stats count values(host) as host, values(TargetDomainName) as Domain, values(user) as user 
| `detect_computer_changed_with_anonymous_account_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `detect_computer_changed_with_anonymous_account_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* TargetUserName
* LogonType
* TargetDomainName
* user


#### How To Implement
This search requires audit computer account management to be enabled on the system in order to generate Event ID 4742. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Event Logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Known False Positives
None thus far found

#### Associated Analytic story
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | The following $EventCode$ occurred on $dest$ by $user$ with Logon Type 3, which may be indicative of the an account or group being changed by an anonymous account. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472) | An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'. | 9.3 |



#### Reference

* [https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/](https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/detect_computer_changed_with_anonymous_account.yml) \| *version*: **1**