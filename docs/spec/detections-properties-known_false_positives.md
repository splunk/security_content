# Untitled string in Detection Schema Schema

```txt
#/properties/knwon_false_positives#/properties/known_false_positives
```

known false postives

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                     |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [detections.spec.json*](../../out/detections.spec.json "open original schema") |

## known_false_positives Type

`string`

## known_false_positives Examples

```yaml
>-
  Administrators can create memory dumps for debugging purposes, but memory
  dumps of the LSASS process would be unusual.

```
