# Welcome to Splunk Security Research 
![](static/logo.png) 

## View Our Content
You can review our analytics stories by category [here](stories_categories.md), or in our [Splunk App](https://github.com/splunk/security-content/releases). 

Is the command line more your flavor? Check out our [API](https://docs.splunkresearch.com/?version=latest):

```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api",
  "available_endpoints": [
    "/stories",
    "/detections",
    "/investigations",
    "/baselines",
    "/responses",
    "/package"
  ]
}
```


## Execute Our Content
We have built the the Analytics Story Execution App [(ASX)](https://github.com/splunk/analytics_story_execution) specifically "run" Analytics Stories in Splunk.

## Test Our Content
The [attack_range](https://http://github.com/splunk/attack_range) project allows you to spin up an enviroment and launch attacks against it in order to test all our detections. 

## Questions?
Stuck, need help with any of our tools, see our [support options](https://github.com/splunk/security-content#support). 

## Contribute Content
Ready to give back and contribute your detections back to the community. See our [contributor guide](https://github.com/splunk/security-content#Contributing). 


## Content Spec Documentation 
* [Story](spec/story.spec.md)
* [Detections](spec/detections.spec.md) 
* [Investigations](spec/investigations.spec.md) 
* [Responses](spec/responses.spec.md) 
* [Baselines](spec/baselines.spec.md)



