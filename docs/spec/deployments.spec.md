
# Deployment Schema Schema

```
http://example.com/example.json
```

schema for deployment

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Deployment Schema Properties

| Property | Type | Required | Nullable | Default | Defined by |
|----------|------|----------|----------|---------|------------|
| [alert_action](#alert_action) | `object` | **Required**  | No | `{}` | Deployment Schema (this schema) |
| [date](#date) | `string` | **Required**  | No | `""` | Deployment Schema (this schema) |
| [description](#description) | `string` | **Required**  | No | `""` | Deployment Schema (this schema) |
| [id](#id) | `string` | **Required**  | No | `""` | Deployment Schema (this schema) |
| [name](#name) | `string` | **Required**  | No | `""` | Deployment Schema (this schema) |
| [scheduling](#scheduling) | `object` | **Required**  | No | `{}` | Deployment Schema (this schema) |
| [tags](#tags) | `object` | **Required**  | No | `{}` | Deployment Schema (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## alert_action

Set alert action parameter for search

`alert_action`

* is **required**
* type: `object`
* default: `{}`
* defined in this schema

### alert_action Type


`object` with following properties:


| Property | Type | Required | Default |
|----------|------|----------|---------|
| `email`| object | Optional | `{}` |
| `index`| object | Optional | `{}` |
| `notable`| object | Optional | `{}` |



#### email

By enabling it, an email is sent with the results

`email`

* is optional
* type: `object`
* default: `{}`


##### email Type


`object` with following properties:


| Property | Type | Required | Default |
|----------|------|----------|---------|
| `message`| string | **Required** | `""` |
| `subject`| string | **Required** | `""` |
| `to`| string | **Required** | `""` |



#### message

message of email

`message`

* is **required**
* type: `string`
* default: `""`


##### message Type


`string`






##### message Example

```json
Splunk Alert $name$ triggered %fields%
```




#### subject

Subject of email

`subject`

* is **required**
* type: `string`
* default: `""`


##### subject Type


`string`






##### subject Example

```json
Splunk Alert $name$
```




#### to

Recipient of email

`to`

* is **required**
* type: `string`
* default: `""`


##### to Type


`string`






##### to Example

```json
test@test.com
```





##### email Example

```json
[object Object]
```




#### index

By enabling it, the results are stored in another index

`index`

* is optional
* type: `object`
* default: `{}`


##### index Type


`object` with following properties:


| Property | Type | Required | Default |
|----------|------|----------|---------|
| `name`| string | **Required** | `""` |



#### name

Name of the index

`name`

* is **required**
* type: `string`
* default: `""`


##### name Type


`string`






##### name Example

```json
asx
```





##### index Example

```json
[object Object]
```




#### notable

By enabling it, a notable is generated

`notable`

* is optional
* type: `object`
* default: `{}`


##### notable Type


`object` with following properties:


| Property | Type | Required | Default |
|----------|------|----------|---------|
| `rule_description`| string | **Required** | `""` |
| `rule_title`| string | **Required** | `""` |



#### rule_description

Rule description of the notable event

`rule_description`

* is **required**
* type: `string`
* default: `""`


##### rule_description Type


`string`






##### rule_description Example

```json
%description%
```




#### rule_title

Rule title of the notable event

`rule_title`

* is **required**
* type: `string`
* default: `""`


##### rule_title Type


`string`






##### rule_title Example

```json
%name%
```





##### notable Example

```json
[object Object]
```





### alert_action Example

```json
{
  "email": {
    "message": "Splunk Alert $name$ triggered %fields%",
    "subject": "Splunk Alert $name$",
    "to": "test@test.com"
  },
  "index": {
    "name": "asx"
  },
  "notable": {
    "rule_description": "%description%",
    "rule_title": "%name%"
  }
}
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

description of the deployment configuration

`description`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### description Type


`string`






### description Example

```json
"This deployment configuration provides a standard scheduling policy over all rules."
```


## id

uuid as unique identifier

`id`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### id Type


`string`






### id Example

```json
"fb4c31b0-13e8-4155-8aa5-24de4b8d6717"
```


## name

Name of deployment configuration

`name`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### name Type


`string`






### name Example

```json
"Deployment Configuration all Detections"
```


## scheduling

allows to set scheduling parameter

`scheduling`

* is **required**
* type: `object`
* default: `{}`
* defined in this schema

### scheduling Type


`object` with following properties:


| Property | Type | Required | Default |
|----------|------|----------|---------|
| `cron_schedule`| string | **Required** | `""` |
| `earliest_time`| string | **Required** | `""` |
| `latest_time`| string | **Required** | `""` |
| `schedule_window`| string | Optional | `""` |



#### cron_schedule

Cron schedule to schedule the Splunk searches.

`cron_schedule`

* is **required**
* type: `string`
* default: `""`


##### cron_schedule Type


`string`






##### cron_schedule Example

```json
*/10 * * * *
```




#### earliest_time

earliest time of search

`earliest_time`

* is **required**
* type: `string`
* default: `""`


##### earliest_time Type


`string`






##### earliest_time Example

```json
-10m
```




#### latest_time

latest time of search

`latest_time`

* is **required**
* type: `string`
* default: `""`


##### latest_time Type


`string`






##### latest_time Example

```json
now
```




#### schedule_window

schedule window for search

`schedule_window`

* is optional
* type: `string`
* default: `""`


##### schedule_window Type


`string`






##### schedule_window Example

```json
auto
```





### scheduling Example

```json
{
  "cron_schedule": "*/10 * * * *",
  "earliest_time": "-10m",
  "latest_time": "now",
  "schedule_window": "auto"
}
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
  "analytics_story": "credential_dumping"
}
```

