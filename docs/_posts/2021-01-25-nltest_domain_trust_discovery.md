---
title: "NLTest Domain Trust Discovery"
excerpt: "Domain Trust Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-01-25
toc: true
toc_label: ""
tags:
  - Domain Trust Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the execution of `nltest.exe` with command-line arguments utilized to query for Domain Trust information. Two arguments `/domain trusts`, returns a list of trusted domains, and `/all_trusts`, returns all trusted domains. Red Teams and adversaries alike use NLTest.exe to enumerate the current domain to assist with further understanding where to pivot next.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-01-25
- **Author**: Michael Haag, Splunk
- **ID**: c3e05466-5f22-11eb-ae93-0242ac130002


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery |

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

* PR.PT
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=nltest.exe OR Processes.process_name!=nltest.exe) (Processes.process=*/domain_trusts* OR Processes.process=*/all_trusts*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `nltest_domain_trust_discovery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **nltest_domain_trust_discovery_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Administrators may use nltest for troubleshooting purposes, otherwise, rarely used.

#### Associated Analytic story
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Domain Trust Discovery](/stories/domain_trust_discovery)
* [IcedID](/stories/icedid)
* [Active Directory Discovery](/stories/active_directory_discovery)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Domain trust discovery execution on $dest$ |


#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md)
* [https://malware.news/t/lets-learn-trickbot-implements-network-collector-module-leveraging-cmd-wmi-ldap/19104](https://malware.news/t/lets-learn-trickbot-implements-network-collector-module-leveraging-cmd-wmi-ldap/19104)
* [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)
* [https://www.owasp.org/images/4/4b/Red_Team_Operating_in_a_Modern_Environment.pdf](https://www.owasp.org/images/4/4b/Red_Team_Operating_in_a_Modern_Environment.pdf)
* [https://ss64.com/nt/nltest.html](https://ss64.com/nt/nltest.html)
* [https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/](https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/)
* [https://thedfirreport.com/2020/10/08/ryuks-return/](https://thedfirreport.com/2020/10/08/ryuks-return/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/nltest_domain_trust_discovery.yml) \| *version*: **1**