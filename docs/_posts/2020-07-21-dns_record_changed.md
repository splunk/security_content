---
title: "DNS record changed"
excerpt: "DNS
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - DNS
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search takes the DNS records and their answers results of the discovered_dns_records lookup and finds if any records have changed by searching DNS response from the Network_Resolution datamodel across the last day.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)

- **Last Updated**: 2020-07-21
- **Author**: Jose Hernandez, Splunk
- **ID**: 44d3a43e-dcd5-49f7-8356-5209bb369065


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | Command And Control |

#### Search

```

| inputlookup discovered_dns_records 
| rename answer as discovered_answer 
| join domain[
|tstats `security_content_summariesonly` count values(DNS.record_type) as type, values(DNS.answer) as current_answer values(DNS.src) as src from datamodel=Network_Resolution where DNS.message_type=RESPONSE DNS.answer!="unknown" DNS.answer!="" by DNS.query 
| rename DNS.query as query 
| where query!="unknown" 
| rex field=query "(?<domain>\w+\.\w+?)(?:$
|/)"] 
| makemv delim=" " answer 
|  makemv delim=" " type 
| sort -count 
| table count,src,domain,type,query,current_answer,discovered_answer 
| makemv current_answer  
| mvexpand current_answer 
| makemv discovered_answer 
| eval n=mvfind(discovered_answer, current_answer) 
| where isnull(n) 
| `dns_record_changed_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `dns_record_changed_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [discovered_dns_records](https://github.com/splunk/security_content/blob/develop/lookups/discovered_dns_records.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/discovered_dns_records.csv)

#### Required field
* _time
* DNS.record_type
* DNS.answer
* DNS.src
* DNS.message_type
* DNS.query


#### How To Implement
To successfully implement this search you will need to ensure that DNS data is populating the `Network_Resolution` data model. It also requires that the `discover_dns_record` lookup table be populated by the included support search "Discover DNS record". \
 **Splunk>Phantom Playbook Integration**\
If Splunk>Phantom is also configured in your environment, a Playbook called "DNS Hijack Enrichment" can be configured to run when any results are found by this detection search. The playbook takes in the DNS record changed and uses Geoip, whois, Censys and PassiveTotal to detect if DNS issuers changed. To use this integration, install the Phantom App for Splunk `https://splunkbase.splunk.com/app/3411/`, add the correct hostname to the "Phantom Instance" field in the Adaptive Response Actions when configuring this detection search, and set the corresponding Playbook to active. \
(Playbook Link:`https://my.phantom.us/4.2/playbook/dns-hijack-enrichment/`).\


#### Known False Positives
Legitimate DNS changes can be detected in this search. Investigate, verify and update the list of provided current answers for the domains in question as appropriate.

#### Associated Analytic story
* [DNS Hijacking](/stories/dns_hijacking)


#### Kill Chain Phase
* Command & Control



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/dns_record_changed.yml) \| *version*: **3**