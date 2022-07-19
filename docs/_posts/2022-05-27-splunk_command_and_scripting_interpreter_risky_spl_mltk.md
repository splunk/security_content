---
title: "Splunk Command and Scripting Interpreter Risky SPL MLTK"
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

This detection utilizes machine learning model named "risky_command_abuse" trained from "Splunk Command and Scripting Interpreter Risky SPL MLTK Baseline". It should be scheduled to run hourly to detect whether a user has run searches containing risky SPL from this list https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warninga with abnormally long running time in the past one hour, comparing with his/her past seven days history. This search uses the trained baseline to infer whether a search is an outlier (isOutlier ~= 1.0) or not (isOutlier~= 0.0)

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit)
- **Last Updated**: 2022-05-27
- **Author**: Abhinav Mishra, Kumar Sharad and Xiao Lin, Splunk
- **ID**: 19d0146c-2eae-4e53-8d39-1198a78fa9ca


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

* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 6



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

| tstats sum(Search_Activity.total_run_time) AS run_time, values(Search_Activity.search) as searches, count FROM datamodel=Splunk_Audit.Search_Activity WHERE (Search_Activity.user!="") AND (Search_Activity.total_run_time>1) AND (earliest=-1h@h latest=now) AND (Search_Activity.search IN ("*
| runshellscript *", "*
| collect *","*
| delete *", "*
| fit *", "*
| outputcsv *", "*
| outputlookup *", "*
| run *", "*
| script *", "*
| sendalert *", "*
| sendemail *", "*
| tscolle*")) AND (Search_Activity.search_type=adhoc) AND (Search_Activity.user!=splunk-system-user) BY _time, Search_Activity.user span=1h 
| apply risky_command_abuse 
| fields _time, Search_Activity.user, searches, run_time, IsOutlier(run_time) 
| rename IsOutlier(run_time) as isOutlier, _time as timestamp 
| where isOutlier>0.5 
| `splunk_command_and_scripting_interpreter_risky_spl_mltk_filter`
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **splunk_command_and_scripting_interpreter_risky_spl_mltk_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Search_Activity.search
* Search_Activity.total_run_time
* Search_Activity.user
* Search_Activity.search_type


#### How To Implement
This detection depends on MLTK app which can be found here - https://splunkbase.splunk.com/app/2890/ and the Splunk Audit datamodel which can be found here - https://splunkbase.splunk.com/app/1621/. Baseline model needs to be built using "Splunk Command and Scripting Interpreter Risky SPL MLTK Baseline" before this search can run. Please note that the current search only finds matches exactly one space between separator bar and risky commands.

#### Known False Positives
If the run time of a search exceeds the boundaries of outlier defined by the fitted density function model, false positives can occur, incorrectly labeling a long running search as potentially risky.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 20.0 | 50 | 40 | Abnormally long run time for risk SPL command seen by user $(Search_Activity.user). |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://github.com/splunk/attack_data/raw/master/datasets/attack_techniques/T1203/search_activity.txt](https://github.com/splunk/attack_data/raw/master/datasets/attack_techniques/T1203/search_activity.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_command_and_scripting_interpreter_risky_spl_mltk.yml) \| *version*: **1**