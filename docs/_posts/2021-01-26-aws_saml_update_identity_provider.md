---
title: "AWS SAML Update identity provider"
excerpt: "Valid Accounts"
categories:
  - Cloud
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of updates to SAML provider in AWS. Updates to SAML provider need to be monitored closely as they may indicate possible perimeter compromise of federated credentials, or backdoor access from another cloud provider set by attacker.

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk
- **ID**: 2f0604c6-6030-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`cloudtrail` eventName=UpdateSAMLProvider 
| stats count min(_time) as firstTime max(_time) as lastTime by eventType eventName requestParameters.sAMLProviderArn userIdentity.sessionContext.sessionIssuer.arn sourceIPAddress userIdentity.accessKeyId userIdentity.principalId 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|`aws_saml_update_identity_provider_filter`
```

#### Associated Analytic Story
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Required field
* _time
* eventName
* eventType
* requestParameters.sAMLProviderArn
* userIdentity.sessionContext.sessionIssuer.arn
* sourceIPAddress
* userIdentity.accessKeyId
* userIdentity.principalId


#### Kill Chain Phase


#### Known False Positives
Updating a SAML provider or creating a new one may not necessarily be malicious however it needs to be closely monitored.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | User $userIdentity.principalId$ from IP address $sourceIPAddress$ has trigged an event $eventName$ to update the SAML provider to $requestParameters.sAMLProviderArn$ |




#### Reference

* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html](https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html)
* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/update_saml_provider/update_saml_provider.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/update_saml_provider/update_saml_provider.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_saml_update_identity_provider.yml) \| *version*: **1**