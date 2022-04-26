---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults
layout: splash
header:
  overlay_color: "#000"
  overlay_filter: "0.5"
  overlay_image: /static/splunk_banner.png
  actions:
    - label: "Download"
      url: "https://splunkbase.splunk.com/app/3449/"
excerpt: "Get the latest **FREE** Enterprise Security Content Update (ESCU) App with **795** detections for Splunk."
feature_row:
  - image_path: /static/feature_detection.png
    alt: "customizable"
    title: "Detections"
    excerpt: "See all **795** Splunk Analytics built to find evil 😈."
    url: "/detections"
    btn_class: "btn--primary"
    btn_label: "Explore"
  - image_path: /static/feature_stories.png
    alt: "fully responsive"
    title: "Analytic Stories"
    excerpt: "See all **117** use cases, 📦 of detections built to address a threat."
    url: "/stories"
    btn_class: "btn--primary"
    btn_label: "Explore"
  - image_path: /static/feature_playbooks.png
    alt: "100% free"
    title: "Playbooks"
    excerpt: "See all **31** automated investigation 🔭 and response 🛠 playbooks."
    url: "/playbooks"
    btn_class: "btn--primary"
    btn_label: "Explore"
---


{% include feature_row %}

# Welcome to Splunk Security Content

This project gives you access to our repository of Analytic Stories that are security guides which provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk SOAR playbooks (where available)—all designed to work together to detect, investigate, and respond to threats.

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

## [Detection Coverage](https://mitremap.splunkresearch.com/) 🗺
Below is a snapshot in time of what technique we currently have some detection coverage for. The darker the shade of blue the more detections we have for this particular technique.

[![](mitre-map/coverage.png)](https://mitremap.splunkresearch.com/)

## Questions? 📞
Please use the [GitHub issue tracker](https://github.com/splunk/attack_range/issues) to submit bugs or request features.

If you have questions or need support, you can:

* Join the [#security-research](https://splunk-usergroups.slack.com/archives/C1S5BEF38) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)
* Post a question to [Splunk Answers](http://answers.splunk.com)
* If you are a Splunk Enterprise customer with a valid support entitlement contract and have a Splunk-related question, you can also open a support case on the https://www.splunk.com/ support portal


## Contribute Content 🥰
If you want to help the rest of the security community by sharing your own detections, see our [contributor guide](https://github.com/splunk/security_content/wiki/Contributing-to-the-Project) for more information on how to get involved!
