---
title: "Detect New Login Attempts to Routers"
excerpt: ""
categories:
  - Application
last_modified_at: 2017-09-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search queries the authentication logs for assets that are categorized as routers in the ES Assets and Identity Framework, to identify connections that have not been seen before in the last 30 days.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)

- **Last Updated**: 2017-09-12
- **Author**: Bhavin Patel, Splunk
- **ID**: bce3ed7c-9b1f-42a0-abdf-d8b123a34836

#### Search

```

| tstats `security_content_summariesonly` count earliest(_time) as earliest latest(_time) as latest from datamodel=Authentication where Authentication.dest_category=router by Authentication.dest Authentication.user
| eval isOutlier=if(earliest >= relative_time(now(), "-30d@d"), 1, 0) 
| where isOutlier=1
| `security_content_ctime(earliest)`
| `security_content_ctime(latest)` 
| `drop_dm_object_name("Authentication")` 
| `detect_new_login_attempts_to_routers_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_new_login_attempts_to_routers_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Authentication.dest_category
* Authentication.dest
* Authentication.user


#### How To Implement
To successfully implement this search, you must ensure the network router devices are categorized as "router" in the Assets and identity table. You must also populate the Authentication data model with logs related to users authenticating to routing infrastructure.

#### Known False Positives
Legitimate router connections may appear as new connections

#### Associated Analytic story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/detect_new_login_attempts_to_routers.yml) \| *version*: **1**