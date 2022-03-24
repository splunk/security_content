---
title: "Open Redirect in Splunk Web"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2017-09-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2016-4859
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to look for evidence of exploitation for CVE-2016-4859, the Splunk Open Redirect Vulnerability.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2017-09-19
- **Author**: Bhavin Patel, Splunk
- **ID**: d199fb99-2312-451a-9daa-e5efa6ed76a7

#### Search

```
index=_internal sourcetype=splunk_web_access return_to="/%09/*" 
| `open_redirect_in_splunk_web_filter`
```

#### Macros
The SPL above uses the following Macros:

Note that `open_redirect_in_splunk_web_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
No extra steps needed to implement this search.

#### Known False Positives
None identified

#### Associated Analytic story
* [Splunk Enterprise Vulnerability](/stories/splunk_enterprise_vulnerability)


#### Kill Chain Phase
* Delivery



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2016-4859](https://nvd.nist.gov/vuln/detail/CVE-2016-4859) | Open redirect vulnerability in Splunk Enterprise 6.4.x prior to 6.4.3, Splunk Enterprise 6.3.x prior to 6.3.6, Splunk Enterprise 6.2.x prior to 6.2.10, Splunk Enterprise 6.1.x prior to 6.1.11, Splunk Enterprise 6.0.x prior to 6.0.12, Splunk Enterprise 5.0.x prior to 5.0.16 and Splunk Light prior to 6.4.3 allows to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors. | 5.8 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/open_redirect_in_splunk_web.yml) \| *version*: **1**