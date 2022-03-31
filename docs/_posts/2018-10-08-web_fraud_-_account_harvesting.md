---
title: "Web Fraud - Account Harvesting"
excerpt: "Create Account
"
categories:
  - Deprecated
last_modified_at: 2018-10-08
toc: true
toc_label: ""
tags:
  - Create Account
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is used to identify the creation of multiple user accounts using the same email domain name.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-10-08
- **Author**: Jim Apger, Splunk
- **ID**: bf1d7b5c-df2f-4249-a401-c09fdc221ddf


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Persistence |

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
* DE.DP



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
`stream_http` http_content_type=text* uri="/magento2/customer/account/loginPost/" 
| rex field=cookie "form_key=(?<SessionID>\w+)" 
| rex field=form_data "login\[username\]=(?<Username>[^&
|^$]+)" 
| search Username=* 
| rex field=Username "@(?<email_domain>.*)" 
| stats dc(Username) as UniqueUsernames list(Username) as src_user by email_domain 
| where UniqueUsernames> 25 
| `web_fraud___account_harvesting_filter`
```

#### Macros
The SPL above uses the following Macros:
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that **web_fraud_-_account_harvesting_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_content_type
* uri
* cookie


#### How To Implement
We start with a dataset that provides visibility into the email address used for the account creation. In this example, we are narrowing our search down to the single web page that hosts the Magento2 e-commerce platform (via URI) used for account creation, the single http content-type to grab only the user's clicks, and the http field that provides the username (form_data), for performance reasons.  After we have the username and email domain, we look for numerous account creations per email domain.  Common data sources used for this detection are customized Apache logs or Splunk Stream.

#### Known False Positives
As is common with many fraud-related searches, we are usually looking to attribute risk or synthesize relevant context with loosely written detections that simply detect anamolous behavior. This search will need to be customized to fit your environment&#151;improving its fidelity by counting based on something much more specific, such as a device ID that may be present in your dataset. Consideration for whether the large number of registrations are occuring from a first-time seen domain may also be important.  Extending the search window to look further back in time, or even calculating the average per hour/day for each email domain to look for an anomalous spikes, will improve this search.  You can also use Shannon entropy or Levenshtein Distance (both courtesy of URL Toolbox) to consider the randomness or similarity of the email name or email domain, as the names are often machine-generated.

#### Associated Analytic story
* [Web Fraud Detection](/stories/web_fraud_detection)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://splunkbase.splunk.com/app/2734/](https://splunkbase.splunk.com/app/2734/)
* [https://splunkbase.splunk.com/app/1809/](https://splunkbase.splunk.com/app/1809/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/web_fraud_-_account_harvesting.yml) \| *version*: **1**