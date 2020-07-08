
# Response Schema Schema

```
http://example.com/example.json
```

schema for response

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Response Schema Properties

| Property | Type | Required | Nullable | Default | Defined by |
|----------|------|----------|----------|---------|------------|
| [author](#author) | `string` | **Required**  | No | `""` | Response Schema (this schema) |
| [date](#date) | `string` | **Required**  | No | `""` | Response Schema (this schema) |
| [description](#description) | `string` | **Required**  | No | `""` | Response Schema (this schema) |
| [id](#id) | `string` | **Required**  | No | `""` | Response Schema (this schema) |
| [name](#name) | `string` | **Required**  | No | `""` | Response Schema (this schema) |
| [response_tasks](#response_tasks) | `array` | **Required**  | No | `{}` | Response Schema (this schema) |
| [tags](#tags) | `object` | **Required**  | No | `{}` | Response Schema (this schema) |
| [version](#version) | `integer` | **Required**  | No | `0` | Response Schema (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## author

Author of the response

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

version of detection, e.g. 1 or 2 ...

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

Description of response

`description`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### description Type


`string`






### description Example

```json
"Response example."
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

Name of response

`name`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### name Type


`string`






### name Example

```json
"Response Example"
```


## response_tasks

Response tasks divided into phases

`response_tasks`

* is **required**
* type: `array`
* at least `1` items in the array
* default: `{}`
* defined in this schema

### response_tasks Type


Array type: `array`




### response_tasks Example

```json
{
  "another_phase": [
    {
      "id": "7c72d944-3995-4485-8e57-67b4c353989b",
      "name": "Another investigation"
    }
  ],
  "identification": [
    {
      "id": "c36f3f48-e0bb-4c20-a62a-cdc8f6418892",
      "name": "Investigate Indicator of Compromise Hash"
    },
    {
      "id": "0dc849b2-2eb4-4fd2-add1-b6cc475765f0",
      "name": "Investigate Domains"
    }
  ]
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


## version

version of detection, e.g. 1 or 2 ...

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

