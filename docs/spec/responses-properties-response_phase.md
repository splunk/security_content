# Untitled array in Response Schema Schema

```txt
#/properties/response_phases#/properties/response_phase
```

Response divided into phases. These will used to referenced known response_phase parameters

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                   |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [responses.spec.json*](../../out/responses.spec.json "open original schema") |

## response_phase Type

`array`

## response_phase Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## response_phase Default Value

The default value is:

```json
{}
```

## response_phase Examples

```yaml
preparation:
  - id: 7c72d944-3995-4485-8e57-67b4c353989b
    name: Preparation NIST
identification:
  - id: c36f3f48-e0bb-4c20-a62a-cdc8f6418892
    name: Detection and Analysis
  - id: 0dc849b2-2eb4-4fd2-add1-b6cc475765f0
    name: Analysis

```

# response_phase Properties

| Property              | Type | Required | Nullable    | Defined by |
| :-------------------- | :--- | :------- | :---------- | :--------- |
| Additional Properties | Any  | Optional | can be null |            |

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
