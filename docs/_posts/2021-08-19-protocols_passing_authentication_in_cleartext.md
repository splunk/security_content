---
title: "Protocols passing authentication in cleartext"
excerpt: ""
categories:
  - Network
last_modified_at: 2021-08-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies cleartext protocols at risk of leaking sensitive information. Currently, this consists of legacy protocols such as telnet (port 23), POP3 (port 110), IMAP (port 143), and non-anonymous FTP (port 21) sessions. While some of these protocols may be used over SSL, they typically are found on different assigned ports in those instances.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-08-19
- **Author**: Rico Valdez, Splunk
- **ID**: 6923cd64-17a0-453c-b945-81ac2d8c6db9


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance
* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.PT
* DE.AE
* PR.AC
* PR.DS



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 9
* CIS 14



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.action!=blocked AND All_Traffic.transport="tcp" AND (All_Traffic.dest_port="23" OR All_Traffic.dest_port="143" OR All_Traffic.dest_port="110" OR (All_Traffic.dest_port="21" AND All_Traffic.user != "anonymous")) by All_Traffic.user All_Traffic.src All_Traffic.dest All_Traffic.dest_port 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Traffic")` 
| `protocols_passing_authentication_in_cleartext_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **protocols_passing_authentication_in_cleartext_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.transport
* All_Traffic.dest_port
* All_Traffic.user
* All_Traffic.src
* All_Traffic.dest
* All_Traffic.action


#### How To Implement
This search requires you to be ingesting your network traffic, and populating the Network_Traffic data model. For more accurate result it's better to limit destination to organization private and public IP range, like All_Traffic.dest IN(192.168.0.0/16,172.16.0.0/12,10.0.0.0/8, x.x.x.x/22)

#### Known False Positives
Some networks may use kerberized FTP or telnet servers, however, this is rare.

#### Associated Analytic story
* [Use of Cleartext Protocols](/stories/use_of_cleartext_protocols)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://www.rackaid.com/blog/secure-your-email-and-file-transfers/](https://www.rackaid.com/blog/secure-your-email-and-file-transfers/)
* [https://www.infosecmatter.com/capture-passwords-using-wireshark/](https://www.infosecmatter.com/capture-passwords-using-wireshark/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/protocols_passing_authentication_in_cleartext.yml) \| *version*: **3**