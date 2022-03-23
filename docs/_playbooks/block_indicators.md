---
title: "Block Indicators"
last_modified_at: 2021-01-21
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Palo Alto Networks Firewall
  - CarbonBlack Response
  - OpenDNS Umbrella
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook retrieves IP addresses, domains, and file hashes, blocks them on various services, and adds them to specific blocklists as custom lists.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Palo Alto Networks Firewall](https://splunkbase.splunk.com/apps/#/search/Palo Alto Networks Firewall/product/soar), [CarbonBlack Response](https://splunkbase.splunk.com/apps/#/search/CarbonBlack Response/product/soar), [OpenDNS Umbrella](https://splunkbase.splunk.com/apps/#/search/OpenDNS Umbrella/product/soar)
- **Last Updated**: 2021-01-21
- **Author**: Philip Royer, Splunk
- **ID**: fc0edc76-ff2b-48b0-5f6f-63da6783fd63

#### Associated Detections


#### How To Implement
This playbook uses the following custom lists:  ip_address_blocklist, domain_blocklist, filehash_blocklist. This playbook provides an easy, automated, and straightforward solution to maintaining up-to-date IP address, file, and domain blocklists. The playbook looks for any of the required CEF fields within the container. The CEF value is then cross-referenced with their respective Custom Lists. IP addresses are blocked on a Firewall, while domains are blocked using a blocklist service.  The blocking of these two will prevent access to the IOCs.  Finally, file hashes are blocked using an endpoint protection service, which will prevent the process from running on affected endpoints within a network. After the IOCs are blocked using various apps, they are added to their respective custom lists as to maintain a running blocklist record.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/block_indicators.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/block_indicators.yml) \| *version*: **1**