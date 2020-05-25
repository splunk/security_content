# Welcome to Splunk Security Research! 
![](static/logo.png) 

Thanks for stopping by the Splunk Security Research Team's resource portal! Here you'll find background and links to our security content and other related tools.

Splunk security content is organized into "Analytic Stories," themed security guides that provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk Phantom playbooks (where available)—all built to work together to detect, investigate, and respond to threats. The other apps were designed to help you derive more value from this content. 

## View Our Content
You can review our Analytic Stories by category [here](stories_categories.md), or in our [Splunk App](https://github.com/splunk/security-content/releases). 

If you prefer working with the command line, check out our [API](https://docs.splunkresearch.com/?version=latest):

```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api"
}
```

## Getting Started

Once you've cloned the security-content repo, we recommend using our Analytic Story Execution App [(ASX)](https://github.com/splunk/analytics_story_execution) to execute all of the searches, machine-learning models, and Splunk Phantom playbooks in the story automatically.   

## Test Out The Detections
The [attack_range](https://http://github.com/splunk/attack_range) project allows you to spin up an enviroment and launch attacks against it to test the detections. 

## Questions?
If you get stuck or need help with any of our tools, see our [support options](https://github.com/splunk/security-content#support). 

## Contribute Content
If you want to help the rest of the security community by sharing your own detections, see our [contributor guide](https://github.com/splunk/security-content#Contributing). Digital defenders unite!


## Content Spec Documentation 
* [Story](spec/story.spec.md)
* [Detections](spec/detections.spec.md) 
* [Investigations](spec/investigations.spec.md) 
* [Responses](spec/responses.spec.md) 
* [Baselines](spec/baselines.spec.md)



