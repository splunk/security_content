
from __future__ import absolute_import

# EAI fields
EAI_ACL = 'eai:acl'
EAI_ATTRIBUTES = 'eai:attributes'
EAI_USER = 'eai:userName'
EAI_APP = 'eai:appName'

EAI_FIELD_PREFIX = 'eai:'
EAI_FIELDS = [EAI_ACL, EAI_ATTRIBUTES, EAI_USER, EAI_APP]

# elements of eai:attributes
EAI_ATTRIBUTES_OPTIONAL = 'optionalFields'
EAI_ATTRIBUTES_REQUIRED = 'requiredFields'
EAI_ATTRIBUTES_WILDCARD = 'wildcardFields'


class RestEAI(object):

    def __init__(self, model, user, app, acl=None):
        self.model = model
        default_acl = {
            'owner': user,
            'app': app,
            'global': 1,
            'can_write': 1,
            'modifiable': 1,
            'removable': 1,
            'sharing': 'global',
            'perms': {'read': ['*'], 'write': ['admin']},
        }
        self.acl = acl or default_acl
        self.user = user
        self.app = app
        self.attributes = self._build_attributes()

    @property
    def content(self):
        return {
            EAI_ACL: self.acl,
            EAI_USER: self.user,
            EAI_APP: self.app,
            EAI_ATTRIBUTES: self.attributes,
        }

    def _build_attributes(self):
        optional_fields = []
        required_fields = []
        for field in self.model.fields:
            if field.required:
                required_fields.append(field.name)
            else:
                optional_fields.append(field.name)
        return {
            EAI_ATTRIBUTES_OPTIONAL: optional_fields,
            EAI_ATTRIBUTES_REQUIRED: required_fields,
            EAI_ATTRIBUTES_WILDCARD: [],
        }
