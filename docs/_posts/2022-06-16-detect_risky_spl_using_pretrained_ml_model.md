---
title: "Detect Risky SPL using Pretrained ML Model"
excerpt: "Command and Scripting Interpreter
"
categories:
  - Application
last_modified_at: 2022-06-16
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

The following analytic uses a pretrained machine learning text classifier to detect potentially risky commands. The model is trained independently and then the model file is packaged within ESCU for usage. A command is deemed risky based on the presence of certain trigger keywords, along with the context and the role of the user (please see references). The model uses custom features to predict whether a SPL is risky using text classification. The model takes as input the command text, user and search type and outputs a risk score between [0,1]. A high score indicates higher likelihood of a command being risky. This model is on-prem only.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit)
- **Last Updated**: 2022-06-16
- **Author**: Abhinav Mishra, Kumar Sharad, Namratha Sreekanta and Xiao Lin, Splunk
- **ID**: b4aefb5f-1037-410d-a149-1e091288ba33


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Splunk_Audit.Search_Activity where Search_Activity.search_type=adhoc Search_Activity.user!=splunk-system-user by Search_Activity.search Search_Activity.user Search_Activity.search_type 
| eval spl_text = 'Search_Activity.search'. " " .'Search_Activity.user'. " " .'Search_Activity.search_type'
| dedup spl_text 
| apply risky_spl_pre_trained_model 
| where risk_score > 0.5 
| `drop_dm_object_name(Search_Activity)` 
| table search, user, search_type, risk_score 
| `detect_risky_spl_using_pretrained_ml_model_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **detect_risky_spl_using_pretrained_ml_model_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Search_Activity.search
* Search_Activity.user
* Search_Activity.search_type


#### How To Implement
This detection depends on the MLTK app which can be found here - https://splunkbase.splunk.com/app/2890/ and the Splunk Audit datamodel which can be found here - https://splunkbase.splunk.com/app/1621/. Additionally, you need to be ingesting logs which include Search_Activity.search, Search_Activity.user, Search_Activity.search_type from your endpoints. The risk score threshold should be adjusted based on the environment. The detection uses a custom MLTK model hence we need a few more steps for deployment, as outlined here - https://gist.github.com/ksharad-splunk/be2a62227966049047f5e5c4f2adcabb.

#### Known False Positives
False positives may be present if suspicious behavior is observed, as determined by frequent usage of risky keywords.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 20.0 | 50 | 40 | A potentially risky Splunk command has been run by $user$, kindly review. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://github.com/splunk/attack_data/raw/master/datasets/attack_techniques/T1203/search_activity.txt](https://github.com/splunk/attack_data/raw/master/datasets/attack_techniques/T1203/search_activity.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/detect_risky_spl_using_pretrained_ml_model.yml) \| *version*: **1**