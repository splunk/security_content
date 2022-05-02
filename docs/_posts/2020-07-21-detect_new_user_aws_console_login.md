---
title: "Detect new user AWS Console Login"
excerpt: "Cloud Accounts
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Cloud Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events wherein a console login event by a user was recorded within the last hour, then compares the event to a lookup file of previously seen users (by ARN values) who have logged into the console. The alert is fired if the user has logged into the console for the first time within the last hour. Deprecated now this search is updated to use the Authentication datamodel.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: ada0f478-84a8-4641-a3f3-d82362dffd75


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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

* DE.DP
* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` eventName=ConsoleLogin 
| rename userIdentity.arn as user 
| stats earliest(_time) as firstTime latest(_time) as lastTime by user 
| inputlookup append=t previously_seen_users_console_logins_cloudtrail  
| stats min(firstTime) as firstTime max(lastTime) as lastTime by user 
| eval userStatus=if(firstTime >= relative_time(now(), "-70m@m"), "First Time Logging into AWS Console","Previously Seen User") 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)`
| where userStatus ="First Time Logging into AWS Console"  
| `detect_new_user_aws_console_login_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_new_user_aws_console_login_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. Run the "Previously seen users in AWS CloudTrail" support search only once to create a baseline of previously seen IAM users within the last 30 days. Run "Update previously seen users in AWS CloudTrail" hourly (or more frequently depending on how often you run the detection searches) to refresh the baselines.

#### Known False Positives
When a legitimate new user logins for the first time, this activity will be detected. Check how old the account is and verify that the user activity is legitimate.

#### Associated Analytic story
* [Suspicious AWS Login Activities](/stories/suspicious_aws_login_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_new_user_aws_console_login.yml) \| *version*: **2**