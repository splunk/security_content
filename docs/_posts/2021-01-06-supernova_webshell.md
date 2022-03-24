---
title: "Supernova Webshell"
excerpt: "Web Shell
"
categories:
  - Web
last_modified_at: 2021-01-06
toc: true
toc_label: ""
tags:
  - Web Shell
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search aims to detect the Supernova webshell used in the SUNBURST attack.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)

- **Last Updated**: 2021-01-06
- **Author**: John Stoner, Splunk
- **ID**: 2ec08a09-9ff1-4dac-b59f-1efd57972ec1


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | Persistence |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Web.Web where web.url=*logoimagehandler.ashx*codes* OR Web.url=*logoimagehandler.ashx*clazz* OR Web.url=*logoimagehandler.ashx*method* OR Web.url=*logoimagehandler.ashx*args* by Web.src Web.dest Web.url Web.vendor_product Web.user Web.http_user_agent _time span=1s 
| `supernova_webshell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `supernova_webshell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Web.url
* Web.src
* Web.dest
* Web.vendor_product
* Web.user
* Web.http_user_agent


#### How To Implement
To successfully implement this search, you need to be monitoring web traffic to your Solarwinds Orion. The logs should be ingested into splunk and populating/mapped to the Web data model.

#### Known False Positives
There might be false positives associted with this detection since items like args as a web argument is pretty generic.

#### Associated Analytic story
* [NOBELIUM Group](/stories/nobelium_group)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-supernova-malware-solarwinds-continued.html](https://www.splunk.com/en_us/blog/security/detecting-supernova-malware-solarwinds-continued.html)
* [https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/](https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/supernova_webshell.yml) \| *version*: **1**