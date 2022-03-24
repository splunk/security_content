---
title: "Splunk Enterprise Information Disclosure"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2018-06-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2018-11409
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to look for evidence of exploitation for CVE-2018-11409, a Splunk Enterprise Information Disclosure Bug.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-06-14
- **Author**: David Dorsey, Splunk
- **ID**: f6a26b7b-7e80-4963-a9a8-d836e7534ebd

#### Search

```
index=_internal sourcetype=splunkd_ui_access server-info 
| search clientip!=127.0.0.1 uri_path="*raw/services/server/info/server-info" 
| rename clientip as src_ip, splunk_server as dest 
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(uri) as uri, values(useragent) as http_user_agent, values(user) as user by src_ip, dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `splunk_enterprise_information_disclosure_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `splunk_enterprise_information_disclosure_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
The REST endpoint that exposes system information is also necessary for the proper operation of Splunk clustering and instrumentation. Whitelisting your Splunk systems will reduce false positives.

#### Known False Positives
Retrieving server information may be a legitimate API request. Verify that the attempt is a valid request for information.

#### Associated Analytic story
* [Splunk Enterprise Vulnerability CVE-2018-11409](/stories/splunk_enterprise_vulnerability_cve-2018-11409)


#### Kill Chain Phase
* Delivery



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409) | Splunk through 7.0.1 allows information disclosure by appending __raw/services/server/info/server-info?output_mode=json to a query, as demonstrated by discovering a license key. | 5.0 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/splunk_enterprise_information_disclosure.yml) \| *version*: **1**