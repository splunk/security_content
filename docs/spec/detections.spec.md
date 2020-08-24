
# Detection Schema Schema

```
http://example.com/example.json
```

schema for detections

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Detection Schema Properties

| Property | Type | Required | Nullable | Default | Defined by |
|----------|------|----------|----------|---------|------------|
| [author](#author) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [date](#date) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [description](#description) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [how_to_implement](#how_to_implement) | `string` | Optional  | No | `""` | Detection Schema (this schema) |
| [id](#id) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [known_false_positives](#known_false_positives) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [name](#name) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [references](#references) | `string[]` | Optional  | No | `[]` | Detection Schema (this schema) |
| [search](#search) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [tags](#tags) | `object` | **Required**  | No | `{}` | Detection Schema (this schema) |
| [type](#type) | `string` | **Required**  | No | `""` | Detection Schema (this schema) |
| [version](#version) | `integer` | **Required**  | No | `0` | Detection Schema (this schema) |
| [risk_object](#risk_object) | `string` | **Optional** | No | `""` | ES Schema |
| [risk_object_type](#risk_object_type) | `string` | **Optional** | No | `""` | ES Schema | 	
| [risk_score](#risk_score) | `integer`  | **Optional** | No | `0` | ES Schema | 
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## author

Author of the detection

`author`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### author Type


`string`






### author Example

```json
"Patrick Bareiss, Splunk"
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

A detailed description of the detection

`description`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### description Type


`string`






### description Example

```json
"dbgcore.dll is a specifc DLL for Windows core debugging. It is used to obtain a memory dump of a process. This search detects the usage of this DLL for creating a memory dump of LSASS process. Memory dumps of the LSASS process can be created with tools such as Windows Task Manager or procdump."
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


## known_false_positives

known false postives

`known_false_positives`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### known_false_positives Type


`string`






### known_false_positives Example

```json
"Administrators can create memory dumps for debugging purposes, but memory dumps of the LSASS process would be unusual."
```


## name
### Name of detection

`name`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### name Type


`string`






### name Example

```json
"Access LSASS Memory for Dump Creation"
```


## references

A list of references for this detection

`references`

* is optional
* type: `string[]`

* default: `[]`
* defined in this schema

### references Type


Array type: `string[]`

All items must be of the type:
`string`




  
An explanation about the purpose of this instance.





### references Example

```json
[
  "https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf"
]
```


## search

The Splunk search for the detection

`search`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### search Type


`string`






### search Example

```json
"`sysmon` EventCode=10 TargetImage=*lsass.exe CallTrace=*dbgcore.dll* OR CallTrace=*dbghelp.dll* | stats count min(_time) as firstTime max(_time) as lastTime by Computer, TargetImage, TargetProcessId, SourceImage, SourceProcessId | rename Computer as dest | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` | `access_lsass_memory_for_dump_creation_filter`"
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
  "analytics_story": "credential_dumping",
  "custom_key": "custom_value"
}
```


## type

type of detection

`type`

* is **required**
* type: `string`
* default: `""`
* defined in this schema

### type Type


`string`






### type Example

```json
"ESCU"
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
2
```


## Risk Object Tag

Optional parameter for risk scoring meta-data associated to the detection. The `risk_object` field is the name of the risk object
corresponding to the type of entity the risk is associated too.  

`risk_object`

* is **optional**
* type: `string`
* default `""`
* defined in the SSA Schema

## Risk Object Values

Possible field names can take the possible values:  ``risk_system``, ``src``, ``dest``, ``src_user``, ``user``, ``risk_hash``,
``risk_network``, ``risk_host``, ``risk_other``.

## Risk Object Example 

```json
{
  "risk_object": "src_user",
}
```

## Risk Object Type

The corresponding entity type for the risk score associated to the optional tag ``risk_object_type``.  This is the type of 
object assocaited to the value for the tag `risk_object`

`risk_object_type`

* is **optional**
* type: `string`
* default `""`
* defined in this schema 

## Risk Object Field Types

Possible object types can take the possible values:  ``system``, ``user``, ``hash_values``, ``network_artifacts``, ``host_artifacts``, 
``other``.

## RBA Risk Object Field Example 

```json
{
  "risk_object_type": "system",
}
```

## Risk Object Score

The risk score corresponding to ``risk_object_field`` and ``risk_b.

`risk_object_type`

* is **optional**
* type: `Integer`
* default `0`
* defined in this schema 


## RBA Risk Object Score Example 

```json
{
  "risk_object_score": "60",
}
```