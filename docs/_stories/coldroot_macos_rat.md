---
title: "ColdRoot MacOS RAT"
last_modified_at: 2019-01-09
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Command & Control
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that relate to the ColdRoot Remote Access Trojan that affects MacOS. An example of some of these activities are changing sensative binaries in the MacOS sub-system, detecting process names and executables associated with the RAT, detecting when a keyboard tab is installed on a MacOS machine and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-01-09
- **Author**: Jose Hernandez, Splunk
- **ID**: bd91a2bc-d20b-4f44-a982-1bea98e86390

#### Narrative

Conventional wisdom holds that Apple's MacOS operating system is significantly less vulnerable to attack than Windows machines. While that point is debatable, it is true that attacks against MacOS systems are much less common. However, this fact does not mean that Macs are impervious to breaches. To the contrary, research has shown that that Mac malware is increasing at an alarming rate. According to AV-test, in 2018, there were 86,865 new MacOS malware variants, up from 27,338 the year before&#151;a 31% increase. In contrast, the independent research firm found that new Windows malware had increased from 65.17M to 76.86M during that same period, less than half the rate of growth. The bottom line is that while the numbers look a lot smaller than Windows, it's definitely time to take Mac security more seriously.\
This Analytic Story addresses the ColdRoot remote access trojan (RAT), which was uploaded to Github in 2016, but was still escaping detection by the first quarter of 2018, when a new, more feature-rich variant was discovered masquerading as an Apple audio driver. Among other capabilities, the Pascal-based ColdRoot can heist passwords from users' keychains and remotely control infected machines without detection. In the initial report of his findings, Patrick Wardle, Chief Research Officer for Digita Security, explained that the new ColdRoot RAT could start and kill processes on the breached system, spawn new remote-desktop sessions, take screen captures and assemble them into a live stream of the victim's desktop, and more.\
Searches in this Analytic Story leverage the capabilities of OSquery to address ColdRoot detection from several different angles, such as looking for the existence of associated files and processes, and monitoring for signs of an installed keylogger.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Osquery pack - ColdRoot detection](/deprecated/osquery_pack_-_coldroot_detection/) | None| TTP |
| [MacOS - Re-opened Applications](/endpoint/macos_-_re-opened_applications/) | None| TTP |
| [Processes Tapping Keyboard Events](/endpoint/processes_tapping_keyboard_events/) | None| TTP |

#### Reference

* [https://www.intego.com/mac-security-blog/osxcoldroot-and-the-rat-invasion/](https://www.intego.com/mac-security-blog/osxcoldroot-and-the-rat-invasion/)
* [https://objective-see.com/blog/blog_0x2A.html](https://objective-see.com/blog/blog_0x2A.html)
* [https://www.bleepingcomputer.com/news/security/coldroot-rat-still-undetectable-despite-being-uploaded-on-github-two-years-ago/](https://www.bleepingcomputer.com/news/security/coldroot-rat-still-undetectable-despite-being-uploaded-on-github-two-years-ago/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/coldroot_macos_rat.yml) \| *version*: **1**