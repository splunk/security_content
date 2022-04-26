---
title: "AWS SAML Access by Provider User and Principal"
excerpt: "Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Valid Accounts
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

This search provides specific SAML access from specific Service Provider, user and targeted principal at AWS. This search provides specific information to detect abnormal access or potential credential hijack or forgery, specially in federated environments using SAML protocol inside the perimeter or cloud provider.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk
- **ID**: bbe23980-6019-11eb-ae93-0242ac130002


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` eventName=Assumerolewithsaml 
| stats count min(_time) as firstTime max(_time) as lastTime by requestParameters.principalArn requestParameters.roleArn requestParameters.roleSessionName recipientAccountId responseElements.issuer sourceIPAddress userAgent 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|`aws_saml_access_by_provider_user_and_principal_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **aws_saml_access_by_provider_user_and_principal_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* requestParameters.principalArn
* requestParameters.roleArn
* requestParameters.roleSessionName
* recipientAccountId
* responseElements.issuer
* sourceIPAddress
* userAgent


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs

#### Known False Positives
Attacks using a Golden SAML or SAML assertion hijacks or forgeries are very difficult to detect as accessing cloud providers with these assertions looks exactly like normal access, however things such as source IP sourceIPAddress user, and principal targeted at receiving cloud provider along with endpoint credential access and abuse detection searches can provide the necessary context to detect these attacks.

#### Associated Analytic story
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | From IP address $sourceIPAddress$, user agent $userAgent$ has trigged an event $eventName$ for account ID $recipientAccountId$ |


#### Reference

* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html](https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html)
* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/assume_role_with_saml/assume_role_with_saml.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/assume_role_with_saml/assume_role_with_saml.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_saml_access_by_provider_user_and_principal.yml) \| *version*: **1**