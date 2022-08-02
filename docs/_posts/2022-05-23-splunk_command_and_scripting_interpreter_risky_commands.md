---
title: "Splunk Command and Scripting Interpreter Risky Commands"
excerpt: "Command and Scripting Interpreter
"
categories:
  - Application
last_modified_at: 2022-05-23
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

The Splunk platform contains built-in search processing language (SPL) safeguards to warn you when you are about to unknowingly run a search that contains commands that might be a security risk. This warning appears when you click a link or type a URL that loads a search that contains risky commands. The warning does not appear when you create ad hoc searches. This warning alerts you to the possibility of unauthorized actions by a malicious user. Unauthorized actions include - Copying or transferring data (data exfiltration), Deleting data and Overwriting data. All risky commands may be found here https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warninga. A possible scenario when this might occur is when a malicious actor creates a search that includes commands that exfiltrate or damage data. The malicious actor then sends an unsuspecting user a link to the search. The URL contains a query string (q) and a search identifier (sid), but the sid is not valid. The malicious actor hopes the user will use the link and the search will run. During analysis, pivot based on user name and filter any user or queries not needed. Queries ran from a dashboard are seen as adhoc queries. When a query runs from a dashboard it will not show in audittrail logs the source dashboard name. The query defaults to adhoc and no Splunk system user activity. In addition, modify this query by removing key commands that generate too much noise, or too little, and create separate queries with higher confidence to alert on.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit)
- **Last Updated**: 2022-05-23
- **Author**: Michael Haag, Splunk
- **ID**: 1cf58ae1-9177-40b8-a26c-8966040f11ae


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
| tscolle*") Search_Activity.search_type=adhoc Search_Activity.user!=splunk-system-user by Search_Activity.search Search_Activity.info Search_Activity.total_run_time Search_Activity.user Search_Activity.search_type 
| `drop_dm_object_name(Search_Activity)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `splunk_command_and_scripting_interpreter_risky_commands_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **splunk_command_and_scripting_interpreter_risky_commands_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Search_Activity.search
* Search_Activity.info
* Search_Activity.total_run_time
* Search_Activity.user
* Search_Activity.savedsearch_name
* Search_Activity.search_type


#### How To Implement
To successfully implement this search acceleration is recommended against the Search_Activity datamodel that runs against the splunk _audit index.  In addition, this analytic requires the Common Information Model App which includes the Splunk Audit Datamodel https://splunkbase.splunk.com/app/1621/. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as "curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json". A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Known False Positives
False positives will be present until properly filtered by Username and search name.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 20.0 | 50 | 40 | A risky Splunk command has ran by $user$ and should be reviewed. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_command_and_scripting_interpreter_risky_commands.yml) \| *version*: **1**