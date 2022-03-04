---
title: "Suspicious Zoom Child Processes"
last_modified_at: 2020-04-13
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Attackers are using Zoom as an vector to increase privileges on a sytems. This story detects new child processes of zoom and provides investigative actions for this detection.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-04-13
- **Author**: David Dorsey, Splunk
- **ID**: aa3749a6-49c7-491e-a03f-4eaee5fe0258

#### Narrative

Zoom is a leader in modern enterprise video communications and its usage has increased dramatically with a large amount of the population under stay-at-home orders due to the COVID-19 pandemic. With increased usage has come increased scrutiny and several security flaws have been found with this application on both Windows and macOS systems.\
Current detections focus on finding new child processes of this application on a per host basis. Investigative searches are included to gather information needed during an investigation.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [First Time Seen Child Process of Zoom](/endpoint/first_time_seen_child_process_of_zoom/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation)| Anomaly |

#### Reference

* [https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/](https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/)
* [https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/](https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_zoom_child_processes.yml) \| *version*: **1**