
# Analytic Story Manifest Schema

```
https://api.splunkresearch.com/schemas/story.json
```

The fields that make up the manifest of a version 2 Analytic Story

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Analytic Story Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [category](#category) | `enum` | **Required**  | No | Analytic Story Manifest (this schema) |
| [channel](#channel) | `string` | Optional  | No | Analytic Story Manifest (this schema) |
| [creation_date](#creation_date) | `string` | Optional  | No | Analytic Story Manifest (this schema) |
| [description](#description) | `string` | **Required**  | No | Analytic Story Manifest (this schema) |
| [detections](#detections) | `object[]` | **Required**  | No | Analytic Story Manifest (this schema) |
| [id](#id) | `string` | **Required**  | No | Analytic Story Manifest (this schema) |
| [maintainers](#maintainers) | `object[]` | Optional  | No | Analytic Story Manifest (this schema) |
| [modification_date](#modification_date) | `string` | Optional  | No | Analytic Story Manifest (this schema) |
| [name](#name) | `string` | **Required**  | No | Analytic Story Manifest (this schema) |
| [narrative](#narrative) | `string` | Optional  | No | Analytic Story Manifest (this schema) |
| [original_authors](#original_authors) | `object[]` | Optional  | No | Analytic Story Manifest (this schema) |
| [references](#references) | `string[]` | Optional  | No | Analytic Story Manifest (this schema) |
| [spec_version](#spec_version) | `integer` | Optional  | No | Analytic Story Manifest (this schema) |
| [version](#version) | `string` | **Required**  | No | Analytic Story Manifest (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## category

The category to which the Analytic Story belongs

`category`

* is **required**
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#category-known-values).

### category Known Values
| Value | Description |
|-------|-------------|
| `Abuse` |  |
| `Adversary Tactics` |  |
| `Best Practices` |  |
| `Cloud Security` |  |
| `Malware` |  |
| `Vulnerability` |  |




## channel

A grouping function that designates where this search came from. For example, searches and stories in Enterprise Security Content Updates are in the ESCU channel

`channel`

* is optional
* type: `string`
* defined in this schema

### channel Type


`string`







## creation_date

The date this story was created

`creation_date`

* is optional
* type: `string`
* defined in this schema

### creation_date Type


`string`







## description

A high-level description or goal of the Analytic Story

`description`

* is **required**
* type: `string`
* defined in this schema

### description Type


`string`







## detections

An array of detection mechanisms from Splunk, UBA and phantom.

`detections`

* is **required**
* type: `object[]`
* defined in this schema

### detections Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `detection_id`| string | **Required** |
| `name`| string | **Required** |
| `type`| string | **Required** |



#### detection_id

unique identifier of the detection, in the form of UUID

`detection_id`

* is **required**
* type: `string`

##### detection_id Type


`string`









#### name

Name of the Detection. It can be a name of a Splunk correlation search name, a UBA threat or a Phantom detection playbook.

`name`

* is **required**
* type: `string`

##### name Type


`string`









#### type

What product gives you a detection

`type`

* is **required**
* type: `enum`

The value of this property **must** be equal to one of the [known values below](#detections-known-values).

##### type Known Values
| Value | Description |
|-------|-------------|
| `splunk` |  |
| `uba` |  |
| `phantom` |  |












## id

A unique identifier for the Analytic Story

`id`

* is **required**
* type: `string`
* defined in this schema

### id Type


`string`






### id Example

```json
"8169f17b-ef68-4b59-aae8-5869073014e1"
```


## maintainers

An array of the current maintainers of the Analytic Story.

`maintainers`

* is optional
* type: `object[]`
* defined in this schema

### maintainers Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `company`| string | **Required** |
| `email`| string | **Required** |
| `name`| string | **Required** |



#### company

Company associated with the person maintaining this Analytic Story

`company`

* is **required**
* type: `string`

##### company Type


`string`









#### email

Email address of the person maintaining this Analytic Story

`email`

* is **required**
* type: `string`

##### email Type


`string`









#### name

Name of the person maintaining this Analytic Story

`name`

* is **required**
* type: `string`

##### name Type


`string`















## modification_date

The date of the most recent modification to this Analytic Story

`modification_date`

* is optional
* type: `string`
* defined in this schema

### modification_date Type


`string`







## name

The name of the Analytic Story

`name`

* is **required**
* type: `string`
* defined in this schema

### name Type


`string`







## narrative

Long-form text that describes the Analytic Story and the rationale behind it, as well as an overview of the included searches, and how they enable the story

`narrative`

* is optional
* type: `string`
* defined in this schema

### narrative Type


`string`







## original_authors

An array of the original authors of the Analytic Story

`original_authors`

* is optional
* type: `object[]`
* defined in this schema

### original_authors Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `company`| string | **Required** |
| `email`| string | **Required** |
| `name`| string | **Required** |



#### company

Company associated with the person who originally authored the Analytic Story

`company`

* is **required**
* type: `string`

##### company Type


`string`









#### email

Email address of the person who originally authored the Analytic Story

`email`

* is **required**
* type: `string`

##### email Type


`string`









#### name

Name of the person who originally authored the Analytic Story

`name`

* is **required**
* type: `string`

##### name Type


`string`















## references

An array of URLs that give information about the problem the story is addressing

`references`

* is optional
* type: `string[]`
* at least `0` items in the array
* defined in this schema

### references Type


Array type: `string[]`

All items must be of the type:
`string`










## spec_version

The version of the Analytic Story specification this manifest follows

`spec_version`

* is optional
* type: `integer`
* defined in this schema

### spec_version Type


`integer`







## version

The version of the Analytic Story

`version`

* is **required**
* type: `string`
* defined in this schema

### version Type


`string`






