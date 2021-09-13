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
      url: "https://github.com/splunk/security_content/releases"
excerpt: "Get the latest **FREE** Enterprise Security Content Update (ESCU) App with over 400+ detections for Splunk."
feature_row:
  - image_path: /static/feature_detection.png
    alt: "customizable"
    title: "Detections"
    excerpt: "Splunk Analytics built to find evil 😈."
    url: "/detections"
    btn_class: "btn--primary"
    btn_label: "Explore"
  - image_path: /static/feature_stories.png
    alt: "fully responsive"
    title: "Analytic Stories"
    excerpt: "A groupings 📦 of detections built to solve a use case."
    url: "/stories"
    btn_class: "btn--primary"
    btn_label: "Explore"
  - image_path: /static/feature_playbooks.png
    alt: "100% free"
    title: "Playbooks"
    excerpt: "A set of steps 🐾 to automatically response to a threat."
    url: "/playbooks"
    btn_class: "btn--primary"
    btn_label: "Explore"  
---


{% include feature_row %}  

# Welcome to Splunk Security Content

This project gives you access to our repository of Analytic Stories that are security guides which provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk Phantom playbooks (where available)—all designed to work together to detect, investigate, and respond to threats.

## [Detection Coverage](https://mitremap.splunkresearch.com/)
Below is a snapshot in time of what technique we currently have some detection coverage for. The darker the shade of blue the more detections we have for this particular technique. This map is automatically updated on every release and generated from the [generate-coverage-map.py](https://github.com/splunk/security_content/blob/develop/bin/generate-coverage-map.py).

![](mitre-map/coverage.png)

## View Our Content

* [Analytic Stories](/detections)
* [Detections](/stories)

If you prefer working with the command line, check out our [API](https://docs.splunkresearch.com/?version=latest):

```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api"
}
```

## Test Out The Detections
The [attack_range](https://github.com/splunk/attack_range) project allows you to spin up an enviroment and launch attacks against it to test the detections.

## Questions?
If you get stuck or need help with any of our tools, see our [support options](https://github.com/splunk/security_content#support).

## Contribute Content
If you want to help the rest of the security community by sharing your own detections, see our [contributor guide](https://github.com/splunk/security_content/wiki/Contributing-to-the-Project). Digital defenders unite!


## Content Parts
* [stories/](https://github.com/splunk/security_content/tree/develop/stories): All Analytic Stories
* [detections/](https://github.com/splunk/security_content/tree/develop/detections): Splunk Enterprise, Splunk UBA, and Splunk Phantom detections that power Analytic Stories
* [response_tasks/](https://github.com/splunk/security_content/tree/develop/response_tasks): Splunk Enterprise and Splunk Phantom investigative searches and playbooks employed by Analytic Stories
* [responses/](https://github.com/splunk/security_content/tree/develop/responses): Automated Splunk Enterprise and Splunk Phantom responses triggered by Analytic Stories


#### Content Spec Files
* [stories](https://github.com/splunk/security_content/blob/develop/docs/spec/stories.md)
* [detections](https://github.com/splunk/security_content/blob/develop/docs/spec/detections.md)
* [deployments](https://github.com/splunk/security_content/blob/develop/docs/spec/deployments.md)
* [responses](https://github.com/splunk/security_content/blob/develop/docs/spec/responses.md)
* [response_tasks](https://github.com/splunk/security_content/blob/develop/docs/spec/response_tasks.md)
* [lookups](https://github.com/splunk/security_content/blob/develop/docs/spec/lookups.md)
* [macros](https://github.com/splunk/security_content/blob/develop/docs/spec/macros.md)
