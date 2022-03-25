---
title: "AWS Cross Account Activity From Previously Unseen Account"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2020-05-28
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AssumeRole events where an IAM role in a different account is requested for the first time.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)

- **Last Updated**: 2020-05-28
- **Author**: Rico Valdez, Splunk
- **ID**: 21193641-cb96-4a2c-a707-d9b9a7f7792b

#### Search

```

| tstats min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.signature=AssumeRole by Authentication.vendor_account Authentication.user Authentication.src Authentication.user_role 
| `drop_dm_object_name(Authentication)` 
| rex field=user_role "arn:aws:sts:*:(?<dest_account>.*):" 
| where vendor_account != dest_account 
| rename vendor_account as requestingAccountId dest_account as requestedAccountId 
| lookup previously_seen_aws_cross_account_activity requestingAccountId, requestedAccountId, OUTPUTNEW firstTime 
| eval status = if(firstTime > relative_time(now(), "-24h@h"),"New Cross Account Activity","Previously Seen") 
|  where status = "New Cross Account Activity" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `aws_cross_account_activity_from_previously_unseen_account_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `aws_cross_account_activity_from_previously_unseen_account_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_aws_cross_account_activity](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_aws_cross_account_activity.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_aws_cross_account_activity.csv)

#### Required field
* _time
* Authentication.signature
* Authentication.vendor_account
* Authentication.user
* Authentication.user_role
* Authentication.src


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider. You should run the baseline search `Previously Seen AWS Cross Account Activity - Initial` to build the initial table of source IP address, geographic locations, and times. You must also enable the second baseline search `Previously Seen AWS Cross Account Activity - Update` to keep this table up to date and to age out old data. You can also provide additional filtering for this search by customizing the `aws_cross_account_activity_from_previously_unseen_account_filter` macro.

#### Known False Positives
Using multiple AWS accounts and roles is perfectly valid behavior. It's suspicious when an account requests privileges of an account it hasn't before. You should validate with the account owner that this is a legitimate request.

#### Associated Analytic story
* [Suspicious Cloud Authentication Activities](/stories/suspicious_cloud_authentication_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | AWS account $requestingAccountId$ is trying to access resource from some other account $requestedAccountId$, for the first time. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_cross_account_activity_from_previously_unseen_account.yml) \| *version*: **1**