
# Response Task Schema Schema

```
http://example.com/example.json
```

schema for response tasks

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Response Task Schema Properties

| Property | Type | Required | Nullable | Default | Defined by |
|----------|------|----------|----------|---------|------------|
| [author](#author) | `string` | **Required**  | No | `""` | Response Task Schema (this schema) |
| [dashboard](#dashboard) | `string` | Optional  | No | `""` | Response Task Schema (this schema) |
| [date](#date) | `string` | **Required**  | No | `""` | Response Task Schema (this schema) |
| [description](#description) | `string` | **Required**  | No | `""` | Response Task Schema (this schema) |
| [how_to_implement](#how_to_implement) | `string` | Optional  | No | `""` | Response Task Schema (this schema) |
| [id](#id) | `string` | **Required**  | No | `""` | Response Task Schema (this schema) |
| [inputs](#inputs) | `array` | Optional  | No | `[]` | Response Task Schema (this schema) |
| [name](#name) | `string` | **Required**  | No | `""` | Response Task Schema (this schema) |
| [playbook](#playbook) | `object` | Optional  | No | `{}` | Response Task Schema (this schema) |
| [search](#search) | `string` | Optional  | No | `""` | Response Task Schema (this schema) |
| [version](#version) | `integer` | **Required**  | No | `0` | Response Task Schema (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## author

Author of response task

`author`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### author Type


`string`






### author Example

```json
"Patrick Bareiß, Splunk"
```


## dashboard

Name of dashboard used as response task

`dashboard`

* is optional
* type: `string`
* default: `""`
* defined in this schema

### dashboard Type


`string`






### dashboard Example

```json
"process_chain_analysis.json"
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

Description of response task

`description`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### description Type


`string`






### description Example

```json
"Response Task example description"
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
"fb4c31b0-13e8-4155-8aa5-24de4b8d6717"
```


## inputs

Inputs used from the response task

`inputs`

* is optional
* type: `array`

* default: `[]`
* defined in this schema

### inputs Type


Array type: `array`




### inputs Example

```json
[
  "lookup_file"
]
```


## name

Namo fo response task

`name`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### name Type


`string`






### name Example

```json
"Response Tas Example"
```


## playbook

A phantom playbook as response task

`playbook`

* is optional
* type: `object`
* default: `{}`
* defined in this schema

### playbook Type


`object` with following properties:


| Property | Type | Required | Default |
|----------|------|----------|---------|
| `name`| string | **Required** | `""` |
| `url_json`| string | **Required** | `""` |
| `url_python`| string | **Required** | `""` |



#### name

Name of Phantom Playbook

`name`

* is **required**
* type: `string`
* default: `""`


##### name Type


`string`






##### name Example

```json
lets_encrypt_domain_investigate.json
```




#### url_json

URL for phantom playbook json file

`url_json`

* is **required**
* type: `string`
* default: `""`


##### url_json Type


`string`






##### url_json Example

```json
https://github.com/phantomcyber/playbooks/blob/4.6/lets_encrypt_domain_investigate.json
```




#### url_python

URL for phantom playbook python file

`url_python`

* is **required**
* type: `string`
* default: `""`


##### url_python Type


`string`






##### url_python Example

```json
https://github.com/phantomcyber/playbooks/blob/4.6/lets_encrypt_domain_investigate.py
```





### playbook Example

```json
{
  "name": "lets_encrypt_domain_investigate.json",
  "url_json": "https://github.com/phantomcyber/playbooks/blob/4.6/lets_encrypt_domain_investigate.json",
  "url_python": "https://github.com/phantomcyber/playbooks/blob/4.6/lets_encrypt_domain_investigate.py"
}
```


## search

Search as response task

`search`

* is optional
* type: `string`
* default: `""`
* defined in this schema

### search Type


`string`






### search Example

```json
"`sysmon` EventCode=1 | search [| inputlookup %lookup_file% ] | stats count by dest user process_name"
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
3
```

