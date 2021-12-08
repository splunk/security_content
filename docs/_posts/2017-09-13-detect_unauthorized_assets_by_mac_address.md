---
title: "Detect Unauthorized Assets by MAC address"
excerpt: ""
categories:
  - Network
last_modified_at: 2017-09-13
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Sessions
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

By populating the organization&#39;s assets within the assets_by_str.csv, we will be able to detect unauthorized devices that are trying to connect with the organization&#39;s network by inspecting DHCP request packets, which are issued by devices when they attempt to obtain an IP address from the DHCP server. The MAC address associated with the source of the DHCP request is checked against the list of known devices, and reports on those that are not found.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Sessions](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkSessions)
- **Last Updated**: 2017-09-13
- **Author**: Bhavin Patel, Splunk
- **ID**: dcfd6b40-42f9-469d-a433-2e53f7489ff4

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Network_Sessions where nodename=All_Sessions.DHCP All_Sessions.signature=DHCPREQUEST by All_Sessions.src_ip All_Sessions.dest_mac 
| dedup All_Sessions.dest_mac
| `drop_dm_object_name("Network_Sessions")`
|`drop_dm_object_name("All_Sessions")` 
| search NOT [
| inputlookup asset_lookup_by_str 
|rename mac as dest_mac 
| fields + dest_mac] 
| `detect_unauthorized_assets_by_mac_address_filter`
```

#### Associated Analytic Story
* [Asset Tracking](/stories/asset_tracking)


#### How To Implement
This search uses the Network_Sessions data model shipped with Enterprise Security. It leverages the Assets and Identity framework to populate the assets_by_str.csv file located in SA-IdentityManagement, which will contain a list of known authorized organizational assets including their MAC addresses. Ensure that all inventoried systems have their MAC address populated.

#### Required field
* _time
* All_Sessions.signature
* All_Sessions.src_ip
* All_Sessions.dest_mac


#### Kill Chain Phase
* Reconnaissance
* Delivery
* Actions on Objectives


#### Known False Positives
This search might be prone to high false positives. Please consider this when conducting analysis or investigations. Authorized devices may be detected as unauthorized. If this is the case, verify the MAC address of the system responsible for the false positive and add it to the Assets and Identity framework with the proper information.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_unauthorized_assets_by_mac_address.yml) \| *version*: **1**