---
title: "Clients Connecting to Multiple DNS Servers"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to identify the endpoints that have connected to more than five DNS servers and made DNS Queries over the time frame of the search.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)

- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: 74ec6f18-604b-4202-a567-86b2066be3ce


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |

#### Search

```

| tstats `security_content_summariesonly` count, values(DNS.dest) AS dest dc(DNS.dest) as dest_count from datamodel=Network_Resolution where DNS.message_type=QUERY by DNS.src 
| `drop_dm_object_name("Network_Resolution")` 
|where dest_count > 5 
| `clients_connecting_to_multiple_dns_servers_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `clients_connecting_to_multiple_dns_servers_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.dest
* DNS.message_type
* DNS.src


#### How To Implement
This search requires that DNS data is being ingested and populating the `Network_Resolution` data model. This data can come from DNS logs or from solutions that parse network traffic for this data, such as Splunk Stream or Bro.\
This search produces fields (`dest_count`) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable. To see the additional metadata, add the following fields, if not already present, to Incident Review - Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry):\\n1. **Label:** Distinct DNS Connections, **Field:** dest_count\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives
It's possible that an enterprise has more than five DNS servers that are configured in a round-robin rotation. Please customize the search, as appropriate.

#### Associated Analytic story
* [DNS Hijacking](/stories/dns_hijacking)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Host Redirection](/stories/host_redirection)
* [Command and Control](/stories/command_and_control)


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/clients_connecting_to_multiple_dns_servers.yml) \| *version*: **3**