---
title: "Detect API activity from users without MFA"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2018-05-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user logged into the AWS account, is making API calls and has not enabled Multi Factor authentication. Multi factor authentication adds a layer of security by forcing the users to type a unique authentication code from an approved authentication device when they access AWS websites or services. AWS Best Practices recommend that you enable MFA for privileged IAM users.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-05-17
- **Author**: Bhavin Patel, Splunk
- **ID**: 4d46e8bd-4072-48e4-92db-0325889ef894

#### Search

```
`cloudtrail` userIdentity.sessionContext.attributes.mfaAuthenticated=false 
| search NOT [
| inputlookup aws_service_accounts 
| fields identity 
| rename identity as user]
| stats  count min(_time) as firstTime max(_time) as lastTime values(eventName) as eventName by userIdentity.arn userIdentity.type user 
| `security_content_ctime(firstTime)`  
| `security_content_ctime(lastTime)` 
| `detect_api_activity_from_users_without_mfa_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `detect_api_activity_from_users_without_mfa_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [aws_service_accounts](https://github.com/splunk/security_content/blob/develop/lookups/aws_service_accounts.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/aws_service_accounts.csv)

#### Required field
* _time
* userIdentity.sessionContext.attributes.mfaAuthenticated
* eventName
* userIdentity.arn
* userIdentity.type
* user


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. Leverage the support search `Create a list of approved AWS service accounts`: run it once every 30 days to create a list of service accounts and validate them.\
This search produces fields (`eventName`,`userIdentity.type`,`userIdentity.arn`) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable. To see the additional metadata, add the following fields, if not already present, to Incident Review - Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry):\\n1. **Label:** AWS Event Name, **Field:** eventName\
1. \
1. **Label:** AWS User ARN, **Field:** userIdentity.arn\
1. \
1. **Label:** AWS User Type, **Field:** userIdentity.type\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives
Many service accounts configured within an AWS infrastructure do not have multi factor authentication enabled. Please ignore the service accounts, if triggered and instead add them to the aws_service_accounts.csv file to fine tune the detection. It is also possible that the search detects users in your environment using Single Sign-On systems, since the MFA is not handled by AWS.

#### Associated Analytic story
* [AWS User Monitoring](/stories/aws_user_monitoring)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_api_activity_from_users_without_mfa.yml) \| *version*: **1**