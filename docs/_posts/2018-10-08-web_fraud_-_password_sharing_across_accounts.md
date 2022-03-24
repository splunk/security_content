---
title: "Web Fraud - Password Sharing Across Accounts"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2018-10-08
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is used to identify user accounts that share a common password.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-10-08
- **Author**: Jim Apger, Splunk
- **ID**: 31337a1a-53b9-4e05-96e9-55c934cb71d3

#### Search

```
`stream_http` http_content_type=text* uri=/magento2/customer/account/loginPost*  
| rex field=form_data "login\[username\]=(?<Username>[^&
|^$]+)" 
| rex field=form_data "login\[password\]=(?<Password>[^&
|^$]+)" 
| stats dc(Username) as UniqueUsernames values(Username) as user list(src_ip) as src_ip by Password
|where UniqueUsernames>5 
| `web_fraud___password_sharing_across_accounts_filter`
```

#### Macros
The SPL above uses the following Macros:
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that `web_fraud_-_password_sharing_across_accounts_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_content_type
* uri


#### How To Implement
We need to start with a dataset that allows us to see the values of usernames and passwords that users are submitting to the website hosting the Magento2 e-commerce platform (commonly found in the HTTP form_data field). A tokenized or hashed value of a password is acceptable and certainly preferable to a clear-text password. Common data sources used for this detection are customized Apache logs, customized IIS, and Splunk Stream.

#### Known False Positives
As is common with many fraud-related searches, we are usually looking to attribute risk or synthesize relevant context with loosely written detections that simply detect anamoluous behavior.

#### Associated Analytic story
* [Web Fraud Detection](/stories/web_fraud_detection)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://en.wikipedia.org/wiki/Session_ID](https://en.wikipedia.org/wiki/Session_ID)
* [https://en.wikipedia.org/wiki/Session_(computer_science)](https://en.wikipedia.org/wiki/Session_(computer_science))
* [https://en.wikipedia.org/wiki/HTTP_cookie](https://en.wikipedia.org/wiki/HTTP_cookie)
* [https://splunkbase.splunk.com/app/1809/](https://splunkbase.splunk.com/app/1809/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/web_fraud_-_password_sharing_across_accounts.yml) \| *version*: **1**