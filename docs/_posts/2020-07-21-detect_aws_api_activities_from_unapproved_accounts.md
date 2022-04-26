---
title: "Detect AWS API Activities From Unapproved Accounts"
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

This search looks for successful AWS CloudTrail activity by user accounts that are not listed in the identity table or `aws_service_accounts.csv`. It returns event names and count, as well as the first and last time a specific user or service is detected, grouped by users. Deprecated because managing this list can be quite hard.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: ada0f478-84a8-4641-a3f1-d82362d4bd55


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
* DE.CM
* PR.AC
* ID.AM



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
`cloudtrail` errorCode=success 
| rename userName as identity 
| search NOT [
| inputlookup identity_lookup_expanded 
| fields identity] 
| search NOT [
| inputlookup aws_service_accounts 
| fields identity] 
| rename identity as user 
| stats count min(_time) as firstTime max(_time) as lastTime values(eventName) as eventName by user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_aws_api_activities_from_unapproved_accounts_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_aws_api_activities_from_unapproved_accounts_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [aws_service_accounts](https://github.com/splunk/security_content/blob/develop/lookups/aws_service_accounts.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/aws_service_accounts.csv)

#### Required field
* _time
* errorCode
* userName
* eventName
* user


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You must also populate the `identity_lookup_expanded` lookup shipped with the Asset and Identity framework to be able to look up users in your identity table in Enterprise Security (ES). Leverage the support search called "Create a list of approved AWS service accounts": run it once every 30 days to create and validate a list of service accounts.\
This search produces fields (`eventName`,`firstTime`,`lastTime`) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable. To see the additional metadata, add the following fields, if not already present, to Incident Review - Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry):\\n1. **Label:** AWS Event Name, **Field:** eventName\
1. \
1. **Label:** First Time, **Field:** firstTime\
1. \
1. **Label:** Last Time, **Field:** lastTime\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives
It's likely that you'll find activity detected by users/service accounts that are not listed in the `identity_lookup_expanded` or ` aws_service_accounts.csv` file. If the user is a legitimate service account, update the `aws_service_accounts.csv` table with that entry.

#### Associated Analytic story
* [AWS User Monitoring](/stories/aws_user_monitoring)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_aws_api_activities_from_unapproved_accounts.yml) \| *version*: **2**