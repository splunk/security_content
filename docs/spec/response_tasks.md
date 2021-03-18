# Response Schema


*schema for response task*


## Properties


- **`author`** *(string)*: Author of the response task. Default: ``.

- **`date`** *(string)*: date of creation or modification, format yyyy-mm-dd. Default: ``.

- **`description`** *(string)*: Description of response task. Default: ``.

- **`id`** *(string)*: UUID as unique identifier. Default: ``.

- **`name`** *(string)*: Name of response task. Default: ``.

- **`sla`** *(integer)*: Measured integer for Service Level Agreement for completion of the phase. Default: `0`.

- **`sla_type`** *(string)*: Duration for measured integer for Service Level Agreement for completion of the phase (e.g. minutes, or hours, etc). Default: `minutes`.

- **`automation`** *(object)*: An array of key value pairs for defining actions and playbooks. Can contain additional properties. Default: `{'is_note_required': False, 'sla_type': 'minutes', 'sla': '', 'role': '', 'action': [], 'playbooks': []}`.

- **`tags`** *(object)*: An array of key value pairs for tagging. Can contain additional properties. Default: `{}`.

- **`version`** *(integer)*: version of detection, e.g. 1 or 2 ... Default: `0`.

- **`references`** *(array)*: A list of references for this response, phase or task (e.g. web or printed citation). Default: `[]`.

  - **Items** *(string)*: An explanation about the purpose of this instance. Default: ``.
