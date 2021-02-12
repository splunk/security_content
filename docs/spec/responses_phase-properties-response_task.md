# Untitled array in Response Schema Schema

```txt
#/properties/response_task#/properties/response_task
```

Response phase is divided into task(s) to be completed. These will used to referenced known response_task parameters. Order is as positioned and with unique name.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                               |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [responses_phase.spec.json*](../../out/responses_phase.spec.json "open original schema") |

## response_task Type

`array`

## response_task Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## response_task Default Value

The default value is:

```json
{}
```

## response_task Examples

```yaml
id: 7c72d944-3995-4485-8e57-67b4c353989b
name: Prepare for Incident Handling

```

```yaml
id: c36f3f48-e0bb-4c20-a62a-cdc8f6418892
name: Preventing Incidents

```

```yaml
id: 0dc849b2-2eb4-4fd2-add1-b6cc475765f0
name: Practice

```

# response_task Properties

| Property              | Type | Required | Nullable    | Defined by |
| :-------------------- | :--- | :------- | :---------- | :--------- |
| Additional Properties | Any  | Optional | can be null |            |

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
