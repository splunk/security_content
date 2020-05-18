
# Baseline Schema Schema

```
http://example.com/example.json
```

schema for baselines

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Baseline Schema Properties

| Property | Type | Required | Nullable | Default | Defined by |
|----------|------|----------|----------|---------|------------|
| [author](#author) | `string` | **Required**  | No | `""` | Baseline Schema (this schema) |
| [date](#date) | `string` | **Required**  | No | `""` | Baseline Schema (this schema) |
| [description](#description) | `string` | **Required**  | No | `""` | Baseline Schema (this schema) |
| [how_to_implement](#how_to_implement) | `string` | Optional  | No | `""` | Baseline Schema (this schema) |
| [id](#id) | `string` | **Required**  | No | `""` | Baseline Schema (this schema) |
| [name](#name) | `string` | **Required**  | No | `""` | Baseline Schema (this schema) |
| [search](#search) | `string` | **Required**  | No | `""` | Baseline Schema (this schema) |
| [tags](#tags) | `object` | **Required**  | No | `{}` | Baseline Schema (this schema) |
| [version](#version) | `integer` | **Required**  | No | `0` | Baseline Schema (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## author

Author of the baseline

`author`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### author Type


`string`






### author Example

```json
"Bahvin Patel, Splunk"
```


## date

date of creation or modification, format yyyy-mm-dd

`date`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### date Type


`string`






### date Example

```json
"2019-12-06"
```


## description

A detailed description of the baseline 

`description`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### description Type


`string`






### description Example

```json
"This search looks for CloudTrail events where an AWS instance is started and creates a baseline of most recent time (latest) and the first time (earliest) we've seen this region in our dataset grouped by the value awsRegion for the last 30 days"
```


## how_to_implement

information about how to implement. Only needed for non standard implementations.

`how_to_implement`

* is optional
* type: `string`
* default: `""`
* defined in this schema

### how_to_implement Type


`string`






### how_to_implement Example

```json
"This search requires Sysmon Logs and a Sysmon configuration, which includes EventCode 10 for lsass.exe."
```


## id

UUID as unique identifier

`id`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### id Type


`string`






### id Example

```json
"fc0edc95-ff2b-48b0-9f6f-63da3789fd63"
```


## name
### Name of baseline

`name`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### name Type


`string`






### name Example

```json
"Previously Seen AWS Regions"
```


## search

The Splunk search for the baseline

`search`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### search Type


`string`






### search Example

```json
"cloudtrail StartInstances | stats earliest(_time) as earliest latest(_time) as latest by awsRegion | outputlookup previously_seen_aws_regions.csv"
```


## tags

An array of key value pairs for tagging

`tags`

* is **required**
* type: `object`
* default: `{}`
* defined in this schema

### tags Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|




### tags Example

```json
{
  "analytics_story": "suspicious_aws_ec2_activities",
  "custom_key": "custom_value"
}
```


## version

version of baseline, e.g. 1 or 2 ...

`version`

* is **required**
* type: `integer`
* default: `0`
* defined in this schema

### version Type


`integer`






### version Example

```json
1
```

