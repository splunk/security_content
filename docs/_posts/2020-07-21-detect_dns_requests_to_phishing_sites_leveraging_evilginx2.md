---
title: "Detect DNS requests to Phishing Sites leveraging EvilGinx2"
excerpt: "Spearphishing via Service
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Spearphishing via Service
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for DNS requests for phishing domains that are leveraging EvilGinx tools to mimic websites.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 24dd17b1-e2fb-4c31-878c-d4f226595bfa


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Spearphishing via Service | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery
* Command & Control


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* ID.AM
* PR.DS
* PR.IP
* DE.AE
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8
* CIS 7



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.answer) as answer from datamodel=Network_Resolution.DNS by DNS.dest DNS.src DNS.query host 
| `drop_dm_object_name(DNS)`
| rex field=query ".*?(?<domain>[^./:]+\.(\S{2,3}
|\S{2,3}.\S{2,3}))$" 
| stats count values(query) as query by domain dest src answer
| search `evilginx_phishlets_amazon` OR `evilginx_phishlets_facebook` OR `evilginx_phishlets_github` OR `evilginx_phishlets_0365` OR `evilginx_phishlets_outlook` OR `evilginx_phishlets_aws` OR `evilginx_phishlets_google` 
| search NOT [ inputlookup legit_domains.csv 
| fields domain]
| join domain type=outer [
| tstats count `security_content_summariesonly` values(Web.url) as url from datamodel=Web.Web by Web.dest Web.site 
| rename "Web.*" as * 
| rex field=site ".*?(?<domain>[^./:]+\.(\S{2,3}
|\S{2,3}.\S{2,3}))$" 
| table dest domain url] 
| table count src dest query answer domain url 
| `detect_dns_requests_to_phishing_sites_leveraging_evilginx2_filter`
```

#### Macros
The SPL above uses the following Macros:
* [evilginx_phishlets_0365](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_0365.yml)
* [evilginx_phishlets_aws](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_aws.yml)
* [evilginx_phishlets_facebook](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_facebook.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [evilginx_phishlets_amazon](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_amazon.yml)
* [evilginx_phishlets_outlook](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_outlook.yml)
* [evilginx_phishlets_google](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_google.yml)
* [evilginx_phishlets_github](https://github.com/splunk/security_content/blob/develop/macros/evilginx_phishlets_github.yml)

Note that **detect_dns_requests_to_phishing_sites_leveraging_evilginx2_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.answer
* DNS.dest
* DNS.src
* DNS.query
* host


#### How To Implement
You need to ingest data from your DNS logs in the Network_Resolution datamodel. Specifically you must ingest the domain that is being queried and the IP of the host originating the request. Ideally, you should also be ingesting the answer to the query and the query type. This approach allows you to also create your own localized passive DNS capability which can aid you in future investigations. You will have to add legitimate domain names to the `legit_domains.csv` file shipped with the app. \
 **Splunk>Phantom Playbook Integration**\
If Splunk>Phantom is also configured in your environment, a Playbook called `Lets Encrypt Domain Investigate` can be configured to run when any results are found by this detection search. To use this integration, install the Phantom App for Splunk `https://splunkbase.splunk.com/app/3411/`, add the correct hostname to the "Phantom Instance" field in the Adaptive Response Actions when configuring this detection search, and set the corresponding Playbook to active. \
(Playbook link:`https://my.phantom.us/4.2/playbook/lets-encrypt-domain-investigate/`).\


#### Known False Positives
If a known good domain is not listed in the legit_domains.csv file, then the search could give you false postives. Please update that lookup file to filter out DNS requests to legitimate domains.

#### Associated Analytic story
* [Common Phishing Frameworks](/stories/common_phishing_frameworks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_dns_requests_to_phishing_sites_leveraging_evilginx2.yml) \| *version*: **2**