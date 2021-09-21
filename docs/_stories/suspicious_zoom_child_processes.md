---
title: "Suspicious Zoom Child Processes"
last_modified_at: 2020-04-13
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Attackers are using Zoom as an vector to increase privileges on a sytems. This story detects new child processes of zoom and provides investigative actions for this detection.

- **ID**: aa3749a6-49c7-491e-a03f-4eaee5fe0258
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-04-13
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | None | Hunting |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | None | TTP |
| [First Time Seen Child Process of Zoom](/endpoint/first_time_seen_child_process_of_zoom/) | None | Anomaly |

#### Reference

* [https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/](https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/)
* [https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/](https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_zoom_child_processes.yml) \| *version*: **1**