# Untitled object in Response Schema Schema

```txt
#/properties/automation#/properties/automation
```

An array of key value pairs for defining actions and playbooks

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [response_tasks.spec.json*](../../out/response_tasks.spec.json "open original schema") |

## automation Type

`object` ([Details](response_tasks-properties-automation.md))

## automation Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

## automation Default Value

The default value is:

```json
{
  "is_note_required": false,
  "sla_type": "minutes",
  "sla": "",
  "role": "",
  "action": [],
  "playbooks": []
}
```

## automation Examples

```yaml
is_note_required: false
sla_type: minutes
sla: 30
action:
  - run_query
playbooks:
  - scm: local
    playbook: automate something
  - scm: local
    playbook: automate something else

```

# automation Properties

| Property              | Type | Required | Nullable    | Defined by |
| :-------------------- | :--- | :------- | :---------- | :--------- |
| Additional Properties | Any  | Optional | can be null |            |

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
