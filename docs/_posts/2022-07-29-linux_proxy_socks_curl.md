---
title: "Linux Proxy Socks Curl"
excerpt: "Proxy
, Non-Application Layer Protocol
"
categories:
  - Endpoint
last_modified_at: 2022-07-29
toc: true
toc_label: ""
tags:
  - Proxy
  - Non-Application Layer Protocol
  - Command And Control
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies curl being utilized with a proxy based on command-line arguments - -x, socks, --preproxy and --proxy. This behavior is built into the MetaSploit Framework as a auxiliary module. What does socks buy an adversary? SOCKS4a extends the SOCKS4 protocol to allow a client to specify a destination domain name rather than an IP address. The SOCKS5 protocol is defined in RFC 1928. It is an incompatible extension of the SOCKS4 protocol; it offers more choices for authentication and adds support for IPv6 and UDP, the latter of which can be used for DNS lookups. The protocols, and a proxy itself, allow an adversary to evade controls in place monitoring traffic, making it harder for the defender to identify and track activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-29
- **Author**: Michael Haag, Splunk
- **ID**: bd596c22-ad1e-44fc-b242-817253ce8b08


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | Command And Control |

| [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol | Command And Control |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl Processes.process IN ("*-x *", "*socks4a://*", "*socks5h://*", "*socks4://*","*socks5://*", "*--preproxy *", "--proxy*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_proxy_socks_curl_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **linux_proxy_socks_curl_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be present based on proxy usage internally. Filter as needed.

#### Associated Analytic story
* [Linux Living Off The Land](/stories/linux_living_off_the_land)
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | An instance of $process_name$ was identified on endpoint $dest$ by user $user$ utilizing a proxy. Review activity for further details. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.offensive-security.com/metasploit-unleashed/proxytunnels/](https://www.offensive-security.com/metasploit-unleashed/proxytunnels/)
* [https://curl.se/docs/manpage.html](https://curl.se/docs/manpage.html)
* [https://en.wikipedia.org/wiki/SOCKS](https://en.wikipedia.org/wiki/SOCKS)
* [https://oxylabs.io/blog/curl-with-proxy](https://oxylabs.io/blog/curl-with-proxy)
* [https://reqbin.com/req/c-ddxflki5/curl-proxy-server#:~:text=To%20use%20a%20proxy%20with,be%20URL%20decoded%20by%20Curl.](https://reqbin.com/req/c-ddxflki5/curl-proxy-server#:~:text=To%20use%20a%20proxy%20with,be%20URL%20decoded%20by%20Curl.)
* [https://gtfobins.github.io/gtfobins/curl/](https://gtfobins.github.io/gtfobins/curl/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/curl-linux-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/curl-linux-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_proxy_socks_curl.yml) \| *version*: **1**