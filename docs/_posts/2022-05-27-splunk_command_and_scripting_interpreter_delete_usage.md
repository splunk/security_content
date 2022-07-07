---
title: "Splunk Command and Scripting Interpreter Delete Usage"
excerpt: "Command and Scripting Interpreter
"
categories:
  - Application
last_modified_at: 2022-05-27
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32154
  - Splunk_Audit
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of the risky command - Delete - that may be utilized in Splunk to delete some or all data queried for. In order to use Delete in Splunk, one must be assigned the role. This is typically not used and should generate an anomaly if it is used.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit)
- **Last Updated**: 2022-05-27
- **Author**: Michael Haag, Splunk
- **ID**: 8d3d5d5e-ca43-42be-aa1f-bc64375f6b04


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-32154](https://nvd.nist.gov/vuln/detail/CVE-2022-32154) | Dashboards in Splunk Enterprise versions before 9.0 might let an attacker inject risky search commands into a form token when the token is used in a query in a cross-origin request. The result bypasses SPL safeguards for risky commands. See New capabilities can limit access to some custom and potentially risky commands (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/SPLsafeguards#New_capabilities_can_limit_access_to_some_custom_and_potentially_risky_commands) for more information. Note that the attack is browser-based and an attacker cannot exploit it at will. | 4.0 |



</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Splunk_Audit.Search_Activity where Search_Activity.search IN ("*
| delete*") Search_Activity.search_type=adhoc Search_Activity.user!=splunk-system-user by Search_Activity.search Search_Activity.info Search_Activity.total_run_time Search_Activity.user Search_Activity.search_type 
| `drop_dm_object_name(Search_Activity)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `splunk_command_and_scripting_interpreter_delete_usage_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **splunk_command_and_scripting_interpreter_delete_usage_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Search_Activity.search
* Search_Activity.info
* Search_Activity.total_run_time
* Search_Activity.user
* Search_Activity.savedsearch_name
* Search_Activity.search_type


#### How To Implement
To successfully implement this search acceleration is recommended against the Search_Activity datamodel that runs against the splunk _audit index. In addition, this analytic requires the Common Information Model App which includes the Splunk Audit Datamodel https://splunkbase.splunk.com/app/1621/.

#### Known False Positives
False positives may be present if this command is used as a common practice. Filter as needed.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 90 | 30 | $user$ executed the 'delete' command, if this is unexpected it should be reviewed. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_command_and_scripting_interpreter_delete_usage.yml) \| *version*: **1**