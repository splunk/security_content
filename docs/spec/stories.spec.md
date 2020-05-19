
# Analytics Story Schema Schema

```
http://example.com/example.json
```

schema analytics story

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Analytics Story Schema Properties

| Property | Type | Required | Nullable | Default | Defined by |
|----------|------|----------|----------|---------|------------|
| [author](#author) | `string` | **Required**  | No | `""` | Analytics Story Schema (this schema) |
| [date](#date) | `string` | **Required**  | No | `""` | Analytics Story Schema (this schema) |
| [description](#description) | `string` | **Required**  | No | `""` | Analytics Story Schema (this schema) |
| [id](#id) | `string` | **Required**  | No | `""` | Analytics Story Schema (this schema) |
| [name](#name) | `string` | **Required**  | No | `""` | Analytics Story Schema (this schema) |
| [narrative](#narrative) | `string` | **Required**  | No | `""` | Analytics Story Schema (this schema) |
| [search](#search) | `string` | Optional  | No | `""` | Analytics Story Schema (this schema) |
| [tags](#tags) | `object` | **Required**  | No | `{}` | Analytics Story Schema (this schema) |
| [version](#version) | `integer` | **Required**  | No | `0` | Analytics Story Schema (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## author

Author of the analytics story

`author`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### author Type


`string`






### author Example

```json
"Rico Valdez, Patrick Bareiß, Splunk"
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

description of the analytics story

`description`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### description Type


`string`






### description Example

```json
"Uncover activity consistent with credential dumping, a technique where attackers compromise systems and attempt to obtain and exfiltrate passwords."
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
"fb4c31b0-13e8-4155-8aa5-24de4b8d6717"
```


## name

Name of the Analytics Story

`name`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### name Type


`string`






### name Example

```json
"Credential Dumping"
```


## narrative

narrative of the analytics story

`narrative`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### narrative Type


`string`






### narrative Example

```json
"gathering credentials from a target system, often hashed or encrypted, is a common attack technique. Even though the credentials may not be in plain text, an attacker can still exfiltrate the data and set to cracking it offline, on their own systems."
```


## search

An additional Splunk search, which uses the result of the detections

`search`

* is optional
* type: `string`
* default: `""`
* defined in this schema

### search Type


`string`






### search Example

```json
"index=asx mitre_id=t1003 | stats values(source) as detections values(process) as processes values(user) as users values(_time) as time count by dest"
```


## tags

An explanation about the purpose of this instance.

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


## version

version of analytics story, e.g. 1 or 2 ...

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

