---
title: "Asset Tracking"
last_modified_at: 2017-09-13
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Sessions
  - Actions on Objectives
  - Delivery
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Keep a careful inventory of every asset on your network to make it easier to detect rogue devices. Unauthorized/unmanaged devices could be an indication of malicious behavior that should be investigated further.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Sessions](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkSessions)
- **Last Updated**: 2017-09-13
- **Author**: Bhavin Patel, Splunk
- **ID**: 91c676cf-0b23-438d-abee-f6335e1fce77

#### Narrative

This Analytic Story is designed to help you develop a better understanding of what authorized and unauthorized devices are part of your enterprise. This story can help you better categorize and classify assets, providing critical business context and awareness of their assets during an incident. Information derived from this Analytic Story can be used to better inform and support other analytic stories. For successful detection, you will need to leverage the Assets and Identity Framework from Enterprise Security to populate your known assets.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Unauthorized Assets by MAC address](/network/detect_unauthorized_assets_by_mac_address/) | None| TTP |

#### Reference

* [https://www.cisecurity.org/controls/inventory-of-authorized-and-unauthorized-devices/](https://www.cisecurity.org/controls/inventory-of-authorized-and-unauthorized-devices/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/asset_tracking.yml) \| *version*: **1**