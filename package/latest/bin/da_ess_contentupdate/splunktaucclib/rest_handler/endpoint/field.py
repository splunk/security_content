
from __future__ import absolute_import

from ..error import RestError


__all__ = ['RestField']


class RestField(object):
    """
    REST Field.
    """

    def __init__(
            self,
            name,
            required=False,
            encrypted=False,
            default=None,
            validator=None,
            converter=None,
    ):
        self.name = name
        self.required = required
        self.encrypted = encrypted
        self.default = default
        self.validator = validator
        self.converter = converter

    def validate(self, data, existing=None):
        # update case: check required field in data
        if existing and self.name in data and not data.get(self.name) and self.required:
            raise RestError(
                    400,
                    'Required field is missing: %s' % self.name
                )
        value = data.get(self.name)
        if not value and existing is None:
            if self.required:
                raise RestError(
                    400,
                    'Required field is missing: %s' % self.name
                )
            return
        if self.validator is None or not value:
            return

        res = self.validator.validate(value, data)
        if not res:
            raise RestError(400, self.validator.msg)

    def encode(self, data):
        value = data.get(self.name)
        if not value or self.converter is None:
            return
        data[self.name] = self.converter.encode(value, data)

    def decode(self, data):
        value = data.get(self.name)
        if not value or self.converter is None:
            return
        data[self.name] = self.converter.decode(value, data)
